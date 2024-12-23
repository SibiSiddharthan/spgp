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

static int32_t ec_edwards_get_sqrts(ec_group *eg, bignum_t *s1, bignum_t *s2, bignum_t *y)
{
	ec_edwards_curve *parameters = eg->parameters;
	bignum_t *temp = NULL, *num = NULL, *den = NULL;

	bignum_ctx_start(eg->bctx, 3 * bignum_size(eg->bits * 2));

	temp = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	num = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	den = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);

	// Compute y^2
	temp = bignum_sqr(eg->bctx, temp, y);

	// Compute y^2 - 1
	num = bignum_usub_word(num, temp, 1);

	// Compute 1/(dy^2 + 1)
	den = bignum_mul(eg->bctx, den, temp, parameters->d);
	den = bignum_uadd_word(den, den, 1);
	den = bignum_modinv(eg->bctx, den, den, eg->p);

	// Compute (y^2 - 1)/(dy^2 + 1)
	temp = bignum_modmul(eg->bctx, temp, num, den, eg->p);

	if (bignum_modsqrt(eg->bctx, s1, s2, temp, eg->p) == -1)
	{
		bignum_ctx_end(eg->bctx);
		return -1;
	}

	bignum_ctx_end(eg->bctx);

	return 0;
}

uint32_t ec_ed25519_point_encode(ec_point *ep, void *buffer, uint32_t size)
{
	byte_t *out = buffer;

	if (size < 32)
	{
		return 0;
	}

	// Copy y
	memcpy(ep->y->words, buffer, 32);

	// Set the most significant bit as the least significant bit of x
	out[31] |= (ep->x->words[0] & 1) << 8;

	return 32;
}

ec_point *ec_ed25519_point_decode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size)
{
	ec_edwards_curve *parameters = eg->parameters;

	bignum_t *temp = NULL, *u = NULL, *v = NULL, *w = NULL;
	bignum_t *t1 = NULL, *t2 = NULL, *t3 = NULL, *t4 = NULL;

	byte_t *in = buffer;
	byte_t x = 0;

	if (size != 32)
	{
		return NULL;
	}

	x = in[31] >> 7;

	// Copy y (Ignore the most significant byte)
	bignum_set_bytes_le(ep->y, buffer, 31);

	bignum_ctx_start(eg->bctx, 8 * bignum_size(eg->bits * 2));

	temp = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	u = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	v = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	w = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);

	t1 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	t2 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	t3 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	t4 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);

	// Compute y^2
	temp = bignum_sqr(eg->bctx, temp, ep->y);

	// Compute y^2 - 1
	u = bignum_usub_word(u, temp, 1);

	// Compute dy^2 + 1
	v = bignum_mul(eg->bctx, v, temp, parameters->d);
	v = bignum_uadd_word(v, v, 1);

	// p = 5 mod 8
	// Compute uv^3
	t1 = bignum_modsqr(eg->bctx, t1, v, eg->p);     // v^2
	t2 = bignum_modmul(eg->bctx, t2, t1, v, eg->p); // v^3
	w = bignum_modmul(eg->bctx, w, t2, u, eg->p);

	// Compute (uv^7)^((p-5)/8)
	t1 = bignum_modsqr(eg->bctx, t1, t1, eg->p);     // v^4
	t1 = bignum_modmul(eg->bctx, t1, t1, t2, eg->p); // v^7
	t2 = bignum_modmul(eg->bctx, t2, t1, u, eg->p);

	t3 = bignum_copy(t3, eg->p);
	t3 = bignum_usub_word(t3, t3, 5);
	t3 = bignum_rshift(t3, t3, 3);

	t2 = bignum_modexp(eg->bctx, t2, t2, t3, eg->p);

	// Compute u(v^3) * (uv^7)^((p-5)/8)
	w = bignum_modmul(eg->bctx, w, w, t2, eg->p);

	// Compute vw^2
	t4 = bignum_sqr(eg->bctx, t4, w);
	t4 = bignum_modmul(eg->bctx, t4, t4, v, eg->p);

	// Checking for sqrt
	t1 = bignum_copy(t1, u);
	t2 = bignum_sub(t2, eg->p, u); // -u

	if (bignum_cmp(t4, t1) == 0)
	{
		// x = w
	}
	else if (bignum_cmp(t4, t2) == 0)
	{
		// x = w* 2^((p-1)/4)
		t3 = bignum_copy(t3, eg->p);
		t3 = bignum_usub_word(t3, t3, 1);
		t3 = bignum_rshift(t3, t3, 2);

		bignum_one(t4);
		bignum_lshift1(t4, t4);

		t4 = bignum_modexp(eg->bctx, t4, t4, t3, eg->p);

		w = bignum_modmul(eg->bctx, w, w, t4, eg->p);
	}
	else
	{
		// No sqrt
		bignum_ctx_end(eg->bctx);
		return NULL;
	}

	if (w->bits == 0 && x == 1)
	{
		// No sqrt
		bignum_ctx_end(eg->bctx);
		return NULL;
	}

	if ((w->words[0] & 1) == x)
	{
		bignum_copy(ep->x, w);
	}
	else
	{
		bignum_sub(w, eg->p, w);
		bignum_copy(ep->x, w);
	}

	bignum_ctx_end(eg->bctx);

	return ep;
}

uint32_t ec_ed448_point_encode(ec_point *ep, void *buffer, uint32_t size)
{
	byte_t *out = buffer;

	if (size < 57)
	{
		return 0;
	}

	// Copy y
	memcpy(ep->y->words, buffer, 56);

	// Set the most significant bit as the least significant bit of x
	out[56] = (ep->x->words[0] & 1) << 7;

	return 57;
}

ec_point *ec_ed448_point_decode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size)
{
	bignum_t *s1 = NULL, *s2 = NULL;

	byte_t *in = buffer;
	byte_t x = 0;

	bignum_ctx_start(eg->bctx, 2 * bignum_size(eg->bits));

	s1 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);
	s2 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);

	if (size != 57)
	{
		return NULL;
	}

	x = in[56] >> 7;

	// Copy y (Ignore the most significant byte)
	bignum_set_bytes_le(ep->y, buffer, 56);

	if (ec_edwards_get_sqrts(eg, s1, s2, ep->y) == -1)
	{
		bignum_ctx_end(eg->bctx);
		return NULL;
	}

	if ((s1->words[0] & 1) == x)
	{
		bignum_copy(ep->x, s1);
	}
	else
	{
		bignum_copy(ep->x, s2);
	}

	bignum_ctx_end(eg->bctx);

	return ep;
}
