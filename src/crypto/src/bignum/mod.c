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
		bctx = bignum_ctx_new(0);

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
		bctx = bignum_ctx_new(0);

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
		bctx = bignum_ctx_new(0);

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
		bctx = bignum_ctx_new(0);

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
	bignum_t *sq = NULL;
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
		bctx = bignum_ctx_new(0);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, bignum_size(op_bits));

	sq = bignum_ctx_allocate_bignum(bctx, op_bits);

	r = bignum_mod(bctx, r, a, m);
	sq = bignum_copy(sq, r);

	if ((p->words[0] & 0x1) != 0x1)
	{
		bignum_one(r);
	}

	for (uint32_t i = 1; i < p->bits; ++i)
	{
		sq = bignum_modsqr(bctx, sq, sq, m);

		if (p->words[i / BIGNUM_BITS_PER_WORD] & ((bn_word_t)1 << (i % BIGNUM_BITS_PER_WORD)))
		{
			r = bignum_modmul(bctx, r, r, sq, m);
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

bignum_t *bignum_barret_modexp(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *p, bignum_t *m, bignum_t *mu)
{
	bignum_t *sq = NULL, *qt = NULL;
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
		bctx = bignum_ctx_new(0);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, bignum_size(op_bits));

	sq = bignum_ctx_allocate_bignum(bctx, op_bits);
	qt = bignum_ctx_allocate_bignum(bctx, 2 * m->bits);

	if (mu == NULL)
	{
		mu = bignum_ctx_allocate_bignum(bctx, op_bits);
		bignum_one(mu);
		mu = bignum_lshift(mu, mu, ROUND_UP(m->bits, BIGNUM_BITS_PER_WORD) * 2);
		mu = bignum_div(bctx, mu, mu, m);
	}

	if (a->bits > m->bits)
	{
		bignum_barret_udivmod(bctx, a, m, mu, qt, r);
	}

	sq = bignum_copy(sq, r);

	if ((p->words[0] & 0x1) != 0x1)
	{
		bignum_one(r);
	}

	for (uint32_t i = 1; i < p->bits; ++i)
	{
		sq = bignum_sqr(bctx, sq, sq);
		bignum_barret_udivmod(bctx, sq, m, mu, qt, sq);

		if (p->words[i / BIGNUM_BITS_PER_WORD] & ((bn_word_t)1 << (i % BIGNUM_BITS_PER_WORD)))
		{
			r = bignum_mul(bctx, r, r, sq);
			bignum_barret_udivmod(bctx, r, m, mu, qt, r);
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

	bignum_ctx_start(bctx, 3 * bignum_size(m->bits));

	u = bignum_ctx_allocate_bignum(bctx, m->bits);
	v = bignum_ctx_allocate_bignum(bctx, m->bits);
	gcd = bignum_ctx_allocate_bignum(bctx, m->bits);

	status = bignum_euclid_gcdex(bctx, gcd, u, v, m, a);

	if (status != 0)
	{
		bignum_ctx_end(bctx);
		return NULL;
	}

	if (v->sign != m->sign)
	{
		v = bignum_add(v, v, m);
	}

	r = bignum_copy(r, v);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}
