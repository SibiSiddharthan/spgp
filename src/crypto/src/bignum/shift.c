/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>

// NOTE: These routines should also work when r,a point to the same location.

bignum_t *bignum_lshift(bignum_t *r, bignum_t *a, uint32_t shift)
{
	uint32_t required_bits = (a->bits != 0) ? (a->bits + shift) : 0;
	uint32_t word_shift = shift / BIGNUM_BITS_PER_WORD;
	uint32_t bit_shift = shift % BIGNUM_BITS_PER_WORD;

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (required_bits == 0)
	{
		bignum_zero(r);
		return r;
	}

	if (shift == 0)
	{
		bignum_copy(r, a);
		return r;
	}

	uint32_t a_words = BIGNUM_WORD_COUNT(a);
	uint32_t r_words = CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD);

	// Last word
	// r->words[r_words - 1] = ((r_words - 1 - word_shift) < a_words) ? (a->words[r_words - 1 - word_shift] << bit_shift) : 0;
	// r->words[r_words - 1] |= (bit_shift != 0) ? (a->words[r_words - 2 - word_shift] >> (BIGNUM_BITS_PER_WORD - bit_shift)) : 0;

	for (uint32_t i = r_words - 1; i > word_shift; --i)
	{
		r->words[i] = (a_words > (i - word_shift)) ? (a->words[i - word_shift] << bit_shift) : 0;
		r->words[i] |= (bit_shift != 0)
						   ? ((a_words > (i - 1 - word_shift)) ? (a->words[i - 1 - word_shift] >> (BIGNUM_BITS_PER_WORD - bit_shift)) : 0)
						   : 0;
	}

	// First word after zeroes
	r->words[word_shift] = a->words[0] << bit_shift;

	// Zero start of the bignum
	for (uint32_t i = 0; i < word_shift; ++i)
	{
		r->words[i] = 0;
	}

	r->bits = required_bits;
	r->sign = a->sign;

	return r;
}

bignum_t *bignum_rshift(bignum_t *r, bignum_t *a, uint32_t shift)
{
	uint32_t required_bits = (shift < a->bits) ? (a->bits - shift) : 0;
	uint32_t word_shift = shift / BIGNUM_BITS_PER_WORD;
	uint32_t bit_shift = shift % BIGNUM_BITS_PER_WORD;

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (required_bits == 0)
	{
		bignum_zero(r);
		return r;
	}

	if (shift == 0)
	{
		bignum_copy(r, a);
		return r;
	}

	uint32_t r_words = CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD);
	uint32_t a_words = BIGNUM_WORD_COUNT(a);

	for (uint32_t i = 0; i < r_words - 1; ++i)
	{
		r->words[i] = (a->words[i + word_shift] >> bit_shift);
		r->words[i] |= (bit_shift != 0) ? (a->words[i + 1 + word_shift] << (BIGNUM_BITS_PER_WORD - bit_shift)) : 0;
	}

	// Last word
	r->words[r_words - 1] = (a->words[r_words - 1 + word_shift] >> bit_shift);
	r->words[r_words - 1] |=
		((r_words + word_shift) >= a_words) ? 0 : ((bit_shift != 0) ? (a->words[a_words - 1] << (BIGNUM_BITS_PER_WORD - bit_shift)) : 0);

	// Zero rest of the bignum
	for (uint32_t i = r_words; i < CEIL_DIV(r->size, BIGNUM_WORD_SIZE); ++i)
	{
		r->words[i] = 0;
	}

	r->bits = required_bits;
	r->sign = a->sign;

	return r;
}

bignum_t *bignum_lshift1(bignum_t *r, bignum_t *a)
{
	uint32_t required_bits = (a->bits != 0) ? (a->bits + 1) : 0;
	uint32_t a_words = BIGNUM_WORD_COUNT(a);
	uint32_t r_words = CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD);

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (required_bits == 0)
	{
		bignum_zero(r);
		return r;
	}

	// Last word
	if (r_words > a_words)
	{
		r->words[r_words - 1] = (a->words[r_words - 2] >> (BIGNUM_BITS_PER_WORD - 1));
	}

	for (uint32_t i = a_words - 1; i > 0; --i)
	{
		r->words[i] = (a->words[i] << 1) | (a->words[i - 1] >> (BIGNUM_BITS_PER_WORD - 1));
	}

	// First word
	r->words[0] = a->words[0] << 1;

	r->bits = required_bits;
	r->sign = a->sign;

	return r;
}

bignum_t *bignum_rshift1(bignum_t *r, bignum_t *a)
{
	uint32_t required_bits = (a->bits > 1) ? (a->bits - 1) : 0;
	uint32_t a_words = BIGNUM_WORD_COUNT(a);
	uint32_t r_words = CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD);

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (required_bits == 0)
	{
		bignum_zero(r);
		return r;
	}

	for (uint32_t i = 0; i < r_words - 1; ++i)
	{
		r->words[i] = (a->words[i] >> 1) | (a->words[i + 1] << (BIGNUM_BITS_PER_WORD - 1));
	}

	// Last word
	r->words[r_words - 1] = (a->words[r_words - 1] >> 1) | ((r_words < a_words) ? a->words[r_words] << (BIGNUM_BITS_PER_WORD - 1) : 0);

	// Zero the last word if a,r point to the same bignum
	if (a == r)
	{
		if (r_words < a_words)
		{
			r->words[a_words - 1] = 0;
		}
	}

	r->bits = required_bits;
	r->sign = a->sign;

	return r;
}
