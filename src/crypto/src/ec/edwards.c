/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <bignum.h>
#include <ec.h>

#include <ptr.h>

#include <string.h>

uint32_t ec_edwards_point_is_identity(ec_point *a)
{
	// (x,y) = (0,1)
	if (a->x->bits == 0 && a->y->bits == 1)
	{
		return 1;
	}

	return 0;
}

uint32_t ec_edwards_point_on_curve(ec_group *eg, ec_point *a)
{
	uint32_t result = 0;
	ec_edwards_curve *parameters = eg->parameters;

	bignum_t *lhs = NULL, *rhs = NULL;
	bignum_t *xsq = NULL, *ysq = NULL;

	bignum_ctx_start(eg->bctx, 2 * bignum_size(eg->bits) + 2 * bignum_size(eg->bits * 2));

	lhs = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);
	rhs = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);
	xsq = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	ysq = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);

	xsq = bignum_sqr(eg->bctx, xsq, a->x);
	ysq = bignum_sqr(eg->bctx, ysq, a->y);

	// Compute (ax^2 + y^2) % p
	lhs = bignum_modmul(eg->bctx, lhs, xsq, parameters->a, eg->p);
	lhs = bignum_modadd(eg->bctx, lhs, lhs, ysq, eg->p);

	// Compute (1 + d*x^2*y^2) % p
	rhs = bignum_modmul(eg->bctx, rhs, xsq, ysq, eg->p);
	rhs = bignum_modmul(eg->bctx, rhs, rhs, parameters->d, eg->p);
	rhs = bignum_uadd_word(rhs, rhs, 1);

	// Compare
	if (bignum_cmp(lhs, rhs) == 0)
	{
		result = 1;
	}

	bignum_ctx_end(eg->bctx);

	return result;
}


ec_point *ec_edwards_point_double(ec_group *eg, ec_point *r, ec_point *a)
{
	ec_edwards_curve *parameters = eg->parameters;

	bignum_t *lambda = NULL, *inv = NULL;
	bignum_t *x = NULL, *y = NULL, *t = NULL;

	if (r == NULL)
	{
		r = ec_point_new(eg);

		if (r == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(eg->bctx, 4 * bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	lambda = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	inv = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	x = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	y = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	t = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	// Compute lambda = (d*(x*y)^2)
	x = bignum_mul(eg->bctx, x, a->x, a->y);
	lambda = bignum_modsqr(eg->bctx, lambda, x, eg->p);
	lambda = bignum_modmul(eg->bctx, lambda, lambda, parameters->d, eg->p);

	// Compute (1/(1+lambda))
	inv = bignum_copy(inv, lambda);
	inv = bignum_uadd_word(inv, inv, 1);
	inv = bignum_modinv(eg->bctx, inv, inv, eg->p);

	// Compute 2x/(1+lambda)
	x = bignum_lshift1(x, x);
	x = bignum_modmul(eg->bctx, x, x, inv, eg->p);

	// Compute 1/(1-lambda)
	inv = bignum_copy(inv, lambda);
	inv = bignum_usub_word(inv, inv, 1);
	bignum_set_sign(inv, -1);
	inv = bignum_mod(eg->bctx, inv, inv, eg->p);
	inv = bignum_modinv(eg->bctx, inv, inv, eg->p);

	// Compute y = y*y - a*x*x
	t = bignum_sqr(eg->bctx, t, a->x);
	t = bignum_mul(eg->bctx, t, t, parameters->a);
	y = bignum_sqr(eg->bctx, y, a->y);
	x = bignum_modsub(eg->bctx, y, y, t, eg->p);

	// Compute y = (y*y - a*x*x)/(1-lambda)
	y = bignum_modmul(eg->bctx, y, y, inv, eg->p);

	// Copy results
	bignum_copy(r->x, x);
	bignum_copy(r->y, y);

	bignum_ctx_end(eg->bctx);

	return r;
}

ec_point *ec_edwards_point_add(ec_group *eg, ec_point *r, ec_point *a, ec_point *b)
{
	ec_edwards_curve *parameters = eg->parameters;

	bignum_t *lambda = NULL, *inv = NULL, *t1 = NULL, *t2 = NULL;
	bignum_t *x = NULL, *y = NULL;

	if (r == NULL)
	{
		r = ec_point_new(eg);

		if (r == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(eg->bctx, 6 * bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	lambda = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	inv = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	t1 = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	t2 = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	x = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	y = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	// Compute lambda = d*x1*x2*y1*y2
	t1 = bignum_mul(eg->bctx, t1, a->x, b->y);
	t2 = bignum_mul(eg->bctx, t2, a->y, b->x);

	lambda = bignum_modmul(eg->bctx, lambda, t1, t2, eg->p);
	lambda = bignum_modmul(eg->bctx, lambda, lambda, parameters->d, eg->p);

	// Compute (1/(1+lambda))
	inv = bignum_copy(inv, lambda);
	inv = bignum_uadd_word(inv, inv, 1);
	inv = bignum_modinv(eg->bctx, inv, inv, eg->p);

	// Compute (x1y2 + x2y1)/(1+lambda)
	x = bignum_modadd(eg->bctx, x, t1, t2, eg->p);
	x = bignum_modmul(eg->bctx, x, x, inv, eg->p);

	// Compute 1/(1-lambda)
	inv = bignum_copy(inv, lambda);
	inv = bignum_usub_word(inv, inv, 1);
	bignum_set_sign(inv, -1);
	inv = bignum_mod(eg->bctx, inv, inv, eg->p);
	inv = bignum_modinv(eg->bctx, inv, inv, eg->p);

	t1 = bignum_mul(eg->bctx, t1, a->y, b->y);
	t2 = bignum_mul(eg->bctx, t1, a->x, b->x);
	t2 = bignum_mul(eg->bctx, t2, t2, parameters->a);

	y = bignum_modsub(eg->bctx, y, t1, t2, eg->p);
	y = bignum_modmul(eg->bctx, y, y, inv, eg->p);

	// Copy results
	bignum_copy(r->x, x);
	bignum_copy(r->y, y);

	bignum_ctx_end(eg->bctx);

	return r;
}

ec_point *ec_edwards_point_multiply(ec_group *eg, ec_point *r, ec_point *a, bignum_t *n)
{
	ec_point *r0 = NULL, *r1 = NULL;

	bignum_t *x0 = NULL, *y0 = NULL;
	bignum_t *x1 = NULL, *y1 = NULL;

	if (r == NULL)
	{
		r = ec_point_new(eg);

		if (r == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(eg->bctx, 4 * bignum_size(ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	x0 = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	y0 = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	x1 = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	y1 = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	r0->x = x0;
	r0->y = y0;

	ec_point_identity(eg, r0);

	r1->x = x1;
	r1->y = y1;

	bignum_copy(x1, a->x);
	bignum_copy(y1, a->y);

	for (uint32_t i = 1; i < n->bits; ++i)
	{
		if (n->words[i / BIGNUM_BITS_PER_WORD] & ((bn_word_t)1 << (i % BIGNUM_BITS_PER_WORD)))
		{
			r0 = ec_edwards_point_add(eg, r0, r0, r1);
			r1 = ec_edwards_point_double(eg, r1, r1);
		}
		else
		{
			r1 = ec_edwards_point_add(eg, r1, r0, r1);
			r0 = ec_edwards_point_double(eg, r0, r0);
		}
	}

	ec_point_copy(r, r0);

	bignum_ctx_end(eg->bctx);

	return r;
}
