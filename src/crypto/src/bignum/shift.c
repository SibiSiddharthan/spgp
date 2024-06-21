/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <round.h>

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

	if (word_shift > 0)
	{
		// Use memmove here as a,r can be the same.
		memset(r->words, 0, word_shift * BIGNUM_WORD_SIZE);
		memmove((byte_t *)r->words + (word_shift * BIGNUM_WORD_SIZE), a->words, CEIL_DIV(a->bits, 8));
	}

	if (bit_shift > 0)
	{
		uint32_t r_words_count = CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD);
		bn_word_t carry = 0;
		bn_word_t temp = 0;

		for (uint32_t i = 0; i < r_words_count; ++i)
		{
			temp = r->words[i];
			r->words[i] = (r->words[i] << bit_shift) | carry;
			carry = temp >> (BIGNUM_BITS_PER_WORD - bit_shift); // Carry for the next word.
		}
	}

	r->bits = bignum_bitcount(r);
	r->sign = a->sign;

	return r;
}

bignum_t *bignum_rshift(bignum_t *r, bignum_t *a, uint32_t shift)
{
	uint32_t required_bits = a->bits - shift;
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

	if (word_shift > 0)
	{
		// Use memmove here as a,r can be the same.
		memmove(r->words, (byte_t *)a->words + (word_shift * BIGNUM_WORD_SIZE), a->size - (word_shift * BIGNUM_WORD_SIZE));
	}

	if (bit_shift > 0)
	{
		uint32_t r_words_count = CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD);

		for (uint32_t i = 0; i < r_words_count - 1; ++i)
		{
			r->words[i] = (r->words[i] >> bit_shift) | (r->words[i + 1] << (BIGNUM_BITS_PER_WORD - bit_shift));
		}

		// Last word
		r->words[r_words_count - 1] = (r->words[r_words_count] >> bit_shift);
	}

	r->bits = bignum_bitcount(r);
	r->sign = a->sign;

	return r;
}
