/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <round.h>

uint8_t bignum_add_words(uint64_t *r, uint64_t *a, uint64_t *b, uint32_t count);
uint8_t bignum_sub_words(uint64_t *r, uint64_t *a, uint64_t *b, uint32_t count);

void bignum_increment(bn_word_t *r, uint32_t count);
void bignum_2complement(bn_word_t *r, uint32_t count);

bignum_t *bignum_sub(bignum_t *r, bignum_t *a, bignum_t *b)
{
	bignum_t *swap = NULL;
	int32_t sign = a->sign;

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
		// Subract b from a.
		uint8_t borrow = bignum_sub_words(r->words, a->words, b->words, min_words);

		if (borrow)
		{
			// This should only happen if (a < b) and (a->bits == bits).
			bignum_2complement(r->words, min_words);

			r->sign = swap == NULL ? b->sign : a->sign;
		}
		else
		{
			r->sign = swap == NULL ? a->sign : b->sign;
		}
	}
	else
	{
		// Different sign -> add a and b, and set sign.
		uint8_t carry = bignum_add_words(r->words, a->words, b->words, min_words);

		if (total_words - min_words > 0)
		{
			memcpy(r->words + min_words, a->words + min_words, total_words - min_words);
		}

		if (carry)
		{
			bignum_increment(r->words + min_words, CEIL_DIV(1 + a->bits - b->bits, BIGNUM_BITS_PER_WORD));
		}

		r->sign = sign;
	}

	r->bits = bignum_bitcount(r);

	return r;
}
