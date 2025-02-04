/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <ec.h>
#include <bignum.h>
#include <bignum-internal.h>

#include <string.h>

uint32_t ec_edwards_point_is_identity(ec_group *eg, ec_point *a)
{
	UNUSED(eg);

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
	ec_edwards_curve *parameters = eg->edwards_parameters;

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
	ec_edwards_curve *parameters = eg->edwards_parameters;

	bignum_t *lambda = NULL, *inv = NULL, *one = NULL;
	bignum_t *x = NULL, *y = NULL, *t = NULL;

	if (r == NULL)
	{
		r = ec_point_new(eg);

		if (r == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(eg->bctx, 4 * bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)) + bignum_size(1));

	lambda = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	inv = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	x = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	y = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	t = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	one = bignum_ctx_allocate_bignum(eg->bctx, 1);

	bignum_one(one);

	// Compute lambda = (d*(x*y)^2)
	x = bignum_mul(eg->bctx, x, a->x, a->y);
	lambda = bignum_modsqr(eg->bctx, lambda, x, eg->p);
	lambda = bignum_modmul(eg->bctx, lambda, lambda, parameters->d, eg->p);

	// Compute (1/(1+lambda))
	inv = bignum_copy(inv, lambda);
	inv = bignum_modadd(eg->bctx, inv, inv, one, eg->p);
	inv = bignum_modinv(eg->bctx, inv, inv, eg->p);

	// Compute 2x/(1+lambda)
	x = bignum_lshift1(x, x);
	x = bignum_modmul(eg->bctx, x, x, inv, eg->p);

	// Compute 1/(1-lambda)
	inv = bignum_copy(inv, lambda);
	inv = bignum_modsub(eg->bctx, inv, one, inv, eg->p);
	inv = bignum_modinv(eg->bctx, inv, inv, eg->p);

	// Compute y = y*y - a*x*x
	t = bignum_sqr(eg->bctx, t, a->x);
	t = bignum_mul(eg->bctx, t, t, parameters->a);
	y = bignum_sqr(eg->bctx, y, a->y);
	y = bignum_modsub(eg->bctx, y, y, t, eg->p);

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
	ec_edwards_curve *parameters = eg->edwards_parameters;

	bignum_t *lambda = NULL, *inv = NULL, *t1 = NULL, *t2 = NULL, *one = NULL;
	bignum_t *x = NULL, *y = NULL;

	if (r == NULL)
	{
		r = ec_point_new(eg);

		if (r == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(eg->bctx, 6 * bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD) + bignum_size(1)));

	lambda = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	inv = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	t1 = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	t2 = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	x = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	y = bignum_ctx_allocate_bignum(eg->bctx, 3 * eg->bits);
	one = bignum_ctx_allocate_bignum(eg->bctx, 1);

	bignum_one(one);

	// Compute lambda = d*x1*x2*y1*y2
	t1 = bignum_mul(eg->bctx, t1, a->x, b->y);
	t2 = bignum_mul(eg->bctx, t2, a->y, b->x);

	lambda = bignum_modmul(eg->bctx, lambda, t1, t2, eg->p);
	lambda = bignum_modmul(eg->bctx, lambda, lambda, parameters->d, eg->p);

	// Compute (1/(1+lambda))
	inv = bignum_copy(inv, lambda);
	inv = bignum_modadd(eg->bctx, inv, inv, one, eg->p);
	inv = bignum_modinv(eg->bctx, inv, inv, eg->p);

	// Compute (x1y2 + x2y1)/(1+lambda)
	x = bignum_modadd(eg->bctx, x, t1, t2, eg->p);
	x = bignum_modmul(eg->bctx, x, x, inv, eg->p);

	// Compute 1/(1-lambda)
	inv = bignum_copy(inv, lambda);
	inv = bignum_modsub(eg->bctx, inv, one, inv, eg->p);
	inv = bignum_modinv(eg->bctx, inv, inv, eg->p);

	t1 = bignum_mul(eg->bctx, t1, a->y, b->y);
	t2 = bignum_mul(eg->bctx, t2, a->x, b->x);
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

	bignum_ctx_start(eg->bctx, 4 * bignum_size(ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)) + (2 * sizeof(ec_point)));

	x0 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);
	y0 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);

	x1 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);
	y1 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);

	r0 = bignum_ctx_allocate_raw(eg->bctx, sizeof(ec_point));
	r1 = bignum_ctx_allocate_raw(eg->bctx, sizeof(ec_point));

	r0->x = x0;
	r0->y = y0;

	if ((n->words[0] & 0x1) != 0x1)
	{
		ec_point_identity(eg, r0);
	}
	else
	{
		ec_point_copy(r0, a);
	}

	r1->x = x1;
	r1->y = y1;

	bignum_copy(x1, a->x);
	bignum_copy(y1, a->y);

	for (uint32_t i = 1; i < n->bits; ++i)
	{
		r1 = ec_edwards_point_double(eg, r1, r1);

		if (n->words[i / BIGNUM_BITS_PER_WORD] & ((bn_word_t)1 << (i % BIGNUM_BITS_PER_WORD)))
		{
			r0 = ec_edwards_point_add(eg, r0, r0, r1);
		}
	}

	ec_point_copy(r, r0);

	bignum_ctx_end(eg->bctx);

	return r;
}

uint32_t ec_ed25519_point_encode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size, uint32_t flags)
{
	byte_t *out = buffer;

	UNUSED(eg);
	UNUSED(flags);

	if (size < 32)
	{
		return 0;
	}

	// Copy y
	memcpy(buffer, ep->y->words, 32);

	// Set the most significant bit as the least significant bit of x
	out[31] |= (ep->x->words[0] & 1) << 7;

	return 32;
}

ec_point *ec_ed25519_point_decode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size)
{
	ec_edwards_curve *parameters = eg->edwards_parameters;

	bignum_t *temp = NULL, *one = NULL, *u = NULL, *v = NULL, *w = NULL;
	bignum_t *t1 = NULL, *t2 = NULL, *t3 = NULL, *t4 = NULL;

	byte_t buffer_copy[32] = {0};
	byte_t *in = buffer;
	byte_t x = 0;

	if (size != 32)
	{
		return NULL;
	}

	if (ep == NULL)
	{
		ep = ec_point_new(eg);

		if (ep == NULL)
		{
			return NULL;
		}
	}

	x = in[31] >> 7;

	memcpy(buffer_copy, buffer, 32);

	// Mask the last bit.
	buffer_copy[31] &= 0x7F;

	// Copy y (Ignore the most significant bit)
	bignum_set_bytes_le(ep->y, buffer_copy, 32);

	bignum_ctx_start(eg->bctx, 10 * bignum_size(eg->bits * 3));

	temp = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	u = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	v = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	w = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	one = bignum_ctx_allocate_bignum(eg->bctx, 1);

	t1 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	t2 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	t3 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	t4 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);

	bignum_one(one);

	// Compute y^2
	temp = bignum_sqr(eg->bctx, temp, ep->y);

	// Compute y^2 - 1
	u = bignum_modsub(eg->bctx, u, temp, one, eg->p);

	// Compute dy^2 + 1
	v = bignum_mul(eg->bctx, v, temp, parameters->d);
	v = bignum_modadd(eg->bctx, v, v, one, eg->p);

	// p = 5 mod 8
	// Compute uv^3
	t1 = bignum_modsqr(eg->bctx, t1, v, eg->p);     // v^2
	t2 = bignum_modmul(eg->bctx, t2, t1, v, eg->p); // v^3
	w = bignum_modmul(eg->bctx, w, t2, u, eg->p);

	// Compute (uv^7)^((p-5)/8)
	t1 = bignum_modsqr(eg->bctx, t1, t1, eg->p);    // v^4
	t2 = bignum_modmul(eg->bctx, t2, t1, w, eg->p); // uv^7

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

		bignum_set_word(t4, 2);
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

uint32_t ec_ed448_point_encode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size, uint32_t flags)
{
	byte_t *out = buffer;

	UNUSED(eg);
	UNUSED(flags);

	if (size < 57)
	{
		return 0;
	}

	// Copy y
	memcpy(buffer, ep->y->words, 56);

	// Set the most significant bit as the least significant bit of x
	out[56] = (ep->x->words[0] & 1) << 7;

	return 57;
}

ec_point *ec_ed448_point_decode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size)
{
	ec_edwards_curve *parameters = eg->edwards_parameters;

	bignum_t *temp = NULL, *one = NULL, *u = NULL, *v = NULL, *w = NULL;
	bignum_t *t1 = NULL, *t2 = NULL, *t3 = NULL, *t4 = NULL;

	byte_t *in = buffer;
	byte_t x = 0;

	if (size != 57)
	{
		return NULL;
	}

	if (ep == NULL)
	{
		ep = ec_point_new(eg);

		if (ep == NULL)
		{
			return NULL;
		}
	}

	x = in[56] >> 7;

	// Copy y (Ignore the most significant byte)
	bignum_set_bytes_le(ep->y, buffer, 56);

	bignum_ctx_start(eg->bctx, 10 * bignum_size(eg->bits * 3));

	temp = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	u = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	v = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	w = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	one = bignum_ctx_allocate_bignum(eg->bctx, 1);

	t1 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	t2 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	t3 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);
	t4 = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 3);

	bignum_one(one);

	// Compute y^2
	temp = bignum_sqr(eg->bctx, temp, ep->y);

	// Compute y^2 - 1
	u = bignum_modsub(eg->bctx, u, temp, one, eg->p);

	// Compute dy^2 - 1
	v = bignum_mul(eg->bctx, v, temp, parameters->d);
	v = bignum_modsub(eg->bctx, v, v, one, eg->p);

	// p = 3 mod 4
	// Compute u^3v
	t1 = bignum_modsqr(eg->bctx, t1, u, eg->p);     // u^2
	t2 = bignum_modmul(eg->bctx, t2, t1, u, eg->p); // u^3
	w = bignum_modmul(eg->bctx, w, t2, v, eg->p);

	// Compute (u^5v^3)^((p-3)/4)
	t2 = bignum_modmul(eg->bctx, t2, t1, w, eg->p); // u^5v
	t2 = bignum_modmul(eg->bctx, t2, t2, v, eg->p); // u^5v^2
	t2 = bignum_modmul(eg->bctx, t2, t2, v, eg->p); // u^5v^3

	t3 = bignum_copy(t3, eg->p);
	t3 = bignum_usub_word(t3, t3, 3);
	t3 = bignum_rshift(t3, t3, 2);

	t2 = bignum_modexp(eg->bctx, t2, t2, t3, eg->p);

	// Compute (u^3)v * (u^5v^3)^((p-3)/4)
	w = bignum_modmul(eg->bctx, w, w, t2, eg->p);

	// Compute vw^2
	t4 = bignum_sqr(eg->bctx, t4, w);
	t4 = bignum_modmul(eg->bctx, t4, t4, v, eg->p);

	// Checking for sqrt
	if (bignum_cmp(t4, u) != 0)
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
