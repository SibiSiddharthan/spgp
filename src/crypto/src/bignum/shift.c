/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <round.h>

// NOTE: These routines should also work when r,a point to the same location.

bignum_t *bignum_lshift(bignum_t *r, bignum_t *a, uint32_t shift)
{
	uint32_t required_bits = a->bits + shift;
	uint32_t word_shift = shift / BIGNUM_BITS_PER_WORD;
	uint32_t bit_shift = shift % BIGNUM_BITS_PER_WORD;

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
		if ((r->size * 8) < required_bits)
		{
			return NULL;
		}
	}

	uint32_t r_words = CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD);

	for (uint32_t i = r_words - 1; i > word_shift; --i)
	{
		r->words[i] = (a->words[i - word_shift] << bit_shift) | (a->words[i - 1 - word_shift] >> (BIGNUM_BITS_PER_WORD - bit_shift));
	}

	// First word after zeroes
	r->words[word_shift] = a->words[0] << bit_shift;

	// Zero start of the bignum
	for (uint32_t i = 0; i < word_shift; ++i)
	{
		r->words[i] = 0;
	}

	r->bits = bignum_bitcount(r);
	r->sign = a->sign;

	return r;
}

bignum_t *bignum_rshift(bignum_t *r, bignum_t *a, uint32_t shift)
{
	uint32_t required_bits = (shift < a->bits) ? a->bits - shift : 0;
	uint32_t word_shift = shift / BIGNUM_BITS_PER_WORD;
	uint32_t bit_shift = shift % BIGNUM_BITS_PER_WORD;

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
		if ((r->size * 8) < required_bits)
		{
			return NULL;
		}
	}

	if (required_bits == 0)
	{
		bignum_zero(r);
		return r;
	}

	uint32_t r_words = CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD);
	uint32_t a_words = BIGNUM_WORD_COUNT(a);

	for (uint32_t i = 0; i < r_words - 1; ++i)
	{
		r->words[i] = (a->words[i + word_shift] >> bit_shift) | (a->words[i + 1 + word_shift] << (BIGNUM_BITS_PER_WORD - bit_shift));
	}

	// Last word
	r->words[r_words - 1] = (a->words[r_words - 1 + word_shift] >> bit_shift);
	r->words[r_words - 1] |= ((r_words + word_shift) >= a_words) ? 0 : (a->words[a_words - 1] << (BIGNUM_BITS_PER_WORD - bit_shift));

	// Zero rest of the bignum
	for (uint32_t i = r_words; i < CEIL_DIV(r->size, BIGNUM_WORD_SIZE); ++i)
	{
		r->words[i] = 0;
	}

	r->bits = bignum_bitcount(r);
	r->sign = a->sign;

	return r;
}
