/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <round.h>

#include <bignum-internal.h>

void bignum_uadd(bignum_t *r, bignum_t *a, bignum_t *b, uint32_t min_words, uint32_t total_words)
{
	uint8_t carry;
	bn_word_t temp;

	carry = bignum_add_words(r->words, a->words, b->words, min_words);

	for (uint32_t pos = min_words; pos < total_words; ++pos)
	{
		temp = a->words[pos];
		r->words[pos] = a->words[pos] + carry;
		carry = (r->words[pos] < temp);
	}

	if (carry)
	{
		// This will always be big enough.
		r->words[total_words] = 1;
	}

	return;
}

int32_t bignum_usub(bignum_t *r, bignum_t *a, bignum_t *b, uint32_t min_words, uint32_t total_words)
{
	uint8_t borrow;
	bn_word_t temp;

	borrow = bignum_sub_words(r->words, a->words, b->words, min_words);

	for (uint32_t pos = min_words; pos < total_words; ++pos)
	{
		temp = a->words[pos];
		r->words[pos] = a->words[pos] - borrow;
		borrow = (r->words[pos] > temp);
	}

	// This should only happen if (a < b) and (a->bits == bits).
	if (borrow)
	{
		bignum_2complement(r->words, total_words);
		return -1;
	}

	return 1;
}

bignum_t *bignum_add(bignum_t *r, bignum_t *a, bignum_t *b)
{
	bignum_t *swap = NULL;
	uint32_t required_bits = 0;
	uint32_t min_words = 0;
	uint32_t total_words = 0;

	if (a->bits < b->bits)
	{
		// Swap a,b such that |a| > |b|.
		swap = a;
		a = b;
		b = swap;
	}

	required_bits = a->bits;
	min_words = BIGNUM_WORD_COUNT(b);
	total_words = BIGNUM_WORD_COUNT(a);

	if (a->sign == b->sign)
	{
		++required_bits; // For overflow
	}

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (a->sign == b->sign)
	{
		bignum_uadd(r, a, b, min_words, total_words);
		r->sign = a->sign;
	}
	else
	{
		// Different sign, subract b from a.
		int32_t sign = bignum_usub(r, a, b, min_words, total_words);
		r->sign = (sign * a->sign);
	}

	r->bits = bignum_bitcount(r);

	if (r->bits == 0)
	{
		r->sign = 1;
	}

	return r;
}

bignum_t *bignum_sub(bignum_t *r, bignum_t *a, bignum_t *b)
{
	bignum_t *swap = NULL;
	int32_t sign = a->sign;
	int32_t sign2 = sign;

	uint32_t required_bits = 0;
	uint32_t min_words = 0;
	uint32_t total_words = 0;

	if (a->bits < b->bits)
	{
		// Swap a,b such that |a| > |b|.
		swap = a;
		a = b;
		b = swap;

		sign2 = -1 * sign2;
	}

	required_bits = a->bits;
	min_words = BIGNUM_WORD_COUNT(b);
	total_words = BIGNUM_WORD_COUNT(a);

	if (a->sign != b->sign)
	{
		++required_bits; // For overflow
	}

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (a->sign == b->sign)
	{
		int32_t sign3 = bignum_usub(r, a, b, min_words, total_words);
		r->sign = sign3 * sign2;
	}
	else
	{
		// Different sign, add a,b.
		bignum_uadd(r, a, b, min_words, total_words);
		r->sign = sign;
	}

	r->bits = bignum_bitcount(r);

	if (r->bits == 0)
	{
		r->sign = 1;
	}

	return r;
}

bignum_t *bignum_uadd_word(bignum_t *r, bignum_t *a, bn_word_t w)
{
	uint32_t required_bits = a->bits + 1;
	uint8_t carry = 0;

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	r->words[0] = a->words[0] + w;
	carry = (r->words[0] < w);

	if (carry > 0)
	{
		bignum_increment(&r->words[1], BIGNUM_WORD_COUNT(r) - 1);
	}

	r->bits = bignum_bitcount(r);
	r->sign = a->sign;

	return r;
}

bignum_t *bignum_usub_word(bignum_t *r, bignum_t *a, bn_word_t w)
{
	uint32_t required_bits = a->bits;
	uint8_t borrow = 0;
	int8_t sign = 1;

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	r->words[0] = a->words[0] - w;
	borrow = (r->words[0] > w);

	if (borrow > 0)
	{
		if (a->bits <= BIGNUM_BITS_PER_WORD)
		{
			// 2's complement
			r->words[0] = ~r->words[0] + 1;
			sign = -1;
		}
		else
		{
			bignum_decrement(&r->words[1], BIGNUM_WORD_COUNT(r) - 1);
		}
	}

	r->bits = bignum_bitcount(r);
	r->sign = sign * a->sign;

	return r;
}
