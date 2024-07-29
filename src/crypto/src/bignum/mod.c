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

bignum_t *bignum_modexp(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *p, bignum_t *m)
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

	if (p->bits == 0)
	{
		bignum_one(r);
		return r;
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

	r = bignum_mod(bctx, r, a, m);
	temp = bignum_copy(temp, bignum_size(r->bits * 2), r);

	for (uint32_t i = 1; i < p->bits; ++i)
	{
		temp = bignum_modsqr(bctx, temp, temp, m);

		if (p->words[i / BIGNUM_BITS_PER_WORD] & ((bn_word_t)1 << (i % BIGNUM_BITS_PER_WORD)))
		{
			r = bignum_modmul(bctx, r, r, temp, m);
		}
	}

	if (p->sign < 0)
	{
		r = bignum_modinv(bctx, r, r, m);
	}

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}

bignum_t *bignum_modinv(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *m)
{
	int32_t status = 0;

	bignum_t *u = NULL, *v = NULL, *gcd = NULL;
	bignum_ctx *obctx = bctx;

	r = bignum_resize(r, m->bits);

	if (r == NULL)
	{
		return NULL;
	}

	if (obctx == NULL)
	{
		bctx = bignum_ctx_new(0);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, 0);

	u = bignum_ctx_allocate_bignum(bctx, m->bits);
	v = bignum_ctx_allocate_bignum(bctx, m->bits);
	gcd = bignum_ctx_allocate_bignum(bctx, m->bits);

	status = bignum_gcdex(bctx, gcd, u, v, m, a);

	if (status != 0)
	{
		bignum_ctx_end(bctx);
		return NULL;
	}

	if (v->sign != m->sign)
	{
		v = bignum_add(v, v, m);
	}

	r = bignum_copy(r, bignum_size(m->bits), v);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}
