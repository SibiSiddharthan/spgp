/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <round.h>

void bignum_mul_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t a_words, uint32_t b_words, uint32_t r_words);

bignum_t *bignum_mul(bignum_t *r, bignum_t *a, bignum_t *b)
{
	uint32_t required_bits = a->bits + b->bits;

	// Handle zero
	if (a->bits == 0 || b->bits == 0)
	{
		required_bits = 0;
	}

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (a->bits == 0 || b->bits == 0)
	{
		bignum_zero(r);
		return r;
	}

	if (a->bits < b->bits)
	{
		// Swap a,b such that |a| > |b|.
		bignum_t *swap = a;
		a = b;
		b = swap;
	}

	bignum_mul_words(r->words, a->words, b->words, BIGNUM_WORD_COUNT(a), BIGNUM_WORD_COUNT(b),
					 CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD));

	r->sign = a->sign * b->sign;
	r->bits = bignum_bitcount(r);

	return r;
}
