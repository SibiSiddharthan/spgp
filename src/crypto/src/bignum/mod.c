/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <round.h>
#include <minmax.h>

#include <bignum-internal.h>

bignum_t *bignum_modadd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m)
{
	bignum_t *temp = NULL;
	bignum_ctx *obctx = bctx;
	uint32_t required_bits = m->bits;
	uint32_t op_bits = MAX(a->bits, b->bits) + 1;

	// Check zero.
	if (m->bits == 0)
	{
		return NULL;
	}

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (obctx == NULL)
	{
		size_t ctx_size = 0;

		ctx_size += bignum_size(op_bits);                                                  // a + b
		ctx_size += op_bits > m->bits ? bignum_size(op_bits - m->bits) : bignum_size(1);   // (a+b)/m
		ctx_size += (CEIL_DIV(op_bits, BIGNUM_BITS_PER_WORD) + 1) * sizeof(bn_word_t) * 3; // Scratch for division

		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, bignum_size(op_bits));

	temp = bignum_ctx_allocate_bignum(bctx, op_bits);

	temp = bignum_add(temp, a, b);
	r = bignum_mod(bctx, r, temp, m);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}

bignum_t *bignum_modsub(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m)
{
	bignum_t *temp = NULL;
	bignum_ctx *obctx = bctx;
	uint32_t required_bits = m->bits;
	uint32_t op_bits = MAX(a->bits, b->bits) + 1;

	// Check zero.
	if (m->bits == 0)
	{
		return NULL;
	}

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (obctx == NULL)
	{
		size_t ctx_size = 0;

		ctx_size += bignum_size(op_bits);                                                  // a - b
		ctx_size += op_bits > m->bits ? bignum_size(op_bits - m->bits) : bignum_size(1);   // (a-b)/m
		ctx_size += (CEIL_DIV(op_bits, BIGNUM_BITS_PER_WORD) + 1) * sizeof(bn_word_t) * 3; // Scratch for division

		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, bignum_size(op_bits));

	temp = bignum_ctx_allocate_bignum(bctx, op_bits);

	temp = bignum_sub(temp, a, b);
	r = bignum_mod(bctx, r, temp, m);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}

bignum_t *bignum_modmul(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m)
{
	bignum_t *temp = NULL;
	bignum_ctx *obctx = bctx;
	uint32_t required_bits = m->bits;
	uint32_t op_bits = a->bits + b->bits;

	// Check zero.
	if (m->bits == 0)
	{
		return NULL;
	}

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (obctx == NULL)
	{
		size_t ctx_size = 0;

		ctx_size += bignum_size(op_bits);                                                  // a * b
		ctx_size += op_bits > m->bits ? bignum_size(op_bits - m->bits) : bignum_size(1);   // (a*b)/m
		ctx_size += (CEIL_DIV(op_bits, BIGNUM_BITS_PER_WORD) + 1) * sizeof(bn_word_t) * 3; // Scratch for division

		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, bignum_size(op_bits));

	temp = bignum_ctx_allocate_bignum(bctx, op_bits);

	temp = bignum_mul(bctx, temp, a, b);
	r = bignum_mod(bctx, r, temp, m);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}

bignum_t *bignum_modsqr(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *m)
{
	bignum_t *temp = NULL;
	bignum_ctx *obctx = bctx;
	uint32_t required_bits = m->bits;
	uint32_t op_bits = 2 * a->bits;

	// Check zero.
	if (m->bits == 0)
	{
		return NULL;
	}

	r = bignum_resize(r, required_bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (obctx == NULL)
	{
		size_t ctx_size = 0;

		ctx_size += bignum_size(op_bits);                                                  // a * a
		ctx_size += op_bits > m->bits ? bignum_size(op_bits - m->bits) : bignum_size(1);   // (a*a)/m
		ctx_size += (CEIL_DIV(op_bits, BIGNUM_BITS_PER_WORD) + 1) * sizeof(bn_word_t) * 3; // Scratch for division

		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, bignum_size(op_bits));

	temp = bignum_ctx_allocate_bignum(bctx, op_bits);

	temp = bignum_sqr(bctx, temp, a);
	r = bignum_mod(bctx, r, temp, m);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}
