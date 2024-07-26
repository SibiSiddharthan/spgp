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

bignum_t *bignum_mul(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
	bignum_ctx *obctx = bctx;
	bn_word_t *words = NULL;

	size_t ctx_size = BIGNUM_WORD_COUNT(a) + BIGNUM_WORD_COUNT(b);
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

	if (required_bits == 0)
	{
		bignum_zero(r);
		return r;
	}

	if (obctx == NULL)
	{
		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	if (a->bits < b->bits)
	{
		// Swap a,b such that |a| > |b|.
		bignum_t *swap = a;
		a = b;
		b = swap;
	}

	bignum_ctx_start(bctx, ctx_size);

	words = bignum_ctx_allocate_raw(bctx, ctx_size);
	memset(words, 0, ctx_size);

	bignum_mul_words(words, a->words, b->words, BIGNUM_WORD_COUNT(a), BIGNUM_WORD_COUNT(b));
	memcpy(r->words, words, CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD) * BIGNUM_WORD_SIZE);

	r->sign = a->sign * b->sign;
	r->bits = bignum_bitcount(r);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}

bignum_t *bignum_sqr(bignum_ctx *bctx, bignum_t *r, bignum_t *a)
{
	bignum_ctx *obctx = bctx;
	bn_word_t *words = NULL;

	size_t ctx_size = 2 * BIGNUM_WORD_COUNT(a);
	uint32_t required_bits = 2 * a->bits;

	// Handle zero
	if (a->bits == 0)
	{
		required_bits = 0;
	}

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

	if (obctx == NULL)
	{
		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, ctx_size);

	words = bignum_ctx_allocate_raw(bctx, ctx_size);
	memset(words, 0, ctx_size);

	bignum_sqr_words(words, a->words, BIGNUM_WORD_COUNT(a));
	memcpy(r->words, words, CEIL_DIV(required_bits, BIGNUM_BITS_PER_WORD) * BIGNUM_WORD_SIZE);

	r->sign = 1;
	r->bits = bignum_bitcount(r);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}
