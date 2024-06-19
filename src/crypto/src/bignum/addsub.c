/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <round.h>

uint8_t bignum_add_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count);
uint8_t bignum_sub_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count);

void bignum_2complement(bn_word_t *r, uint32_t count);

static void bignum_uadd(bignum_t *r, bignum_t *a, bignum_t *b, uint32_t min_words, uint32_t total_words)
{
	uint8_t carry;

	carry = bignum_add_words(r->words, a->words, b->words, min_words);

	for (uint32_t pos = min_words; pos < total_words; ++pos)
	{
		r->words[pos] = a->words[pos] + carry;
		carry = (r->words == 0);
	}

	if (carry)
	{
		// This will always be big enough.
		r->words[total_words] = 1;
	}

	return;
}

static int32_t bignum_usub(bignum_t *r, bignum_t *a, bignum_t *b, uint32_t min_words, uint32_t total_words)
{
	uint8_t borrow;

	borrow = bignum_sub_words(r->words, a->words, b->words, min_words);

	for (uint32_t pos = min_words; pos < total_words; ++pos)
	{
		r->words[pos] = a->words[pos] - borrow;
		borrow = (r->words[pos] == (bn_word_t)-1);
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
	min_words = CEIL_DIV(b->bits, BIGNUM_BITS_PER_WORD);
	total_words = CEIL_DIV(a->bits, BIGNUM_BITS_PER_WORD);

	if (a->sign == b->sign)
	{
		++required_bits; // For overflow
	}

	if (r == NULL)
	{
		r = bignum_new(required_bits);

		if (r == NULL)
		{
			return NULL;
		}
	}
	else
	{
		if (r->bits < required_bits)
		{
			return NULL;
		}
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
		r->sign = sign * (swap == NULL ? a->sign : b->sign);
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
	min_words = CEIL_DIV(b->bits, BIGNUM_BITS_PER_WORD);
	total_words = CEIL_DIV(a->bits, BIGNUM_BITS_PER_WORD);

	if (a->sign != b->sign)
	{
		++required_bits; // For overflow
	}

	if (r == NULL)
	{
		r = bignum_new(required_bits);

		if (r == NULL)
		{
			return NULL;
		}
	}
	else
	{
		if (r->bits < required_bits)
		{
			return NULL;
		}
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
