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

// NIST P-192
bn_word_t nist_p192_p_words[3] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF};
bn_word_t nist_p192_a_words[3] = {0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF};
bn_word_t nist_p192_b_words[3] = {0xFEB8DEECC146B9B1, 0x0FA7E9AB72243049, 0xFEB8DEECC146B9B1};
bn_word_t nist_p192_gx_words[3] = {0xF4FF0AFD82FF1012, 0x7CBF20EB43A18800, 0x188DA80EB03090F6};
bn_word_t nist_p192_gy_words[3] = {0x73F977A11E794811, 0x631011ED6B24CDD5, 0x07192B95FFC8DA78};

bignum_t nist_p192_p = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_p_words};
bignum_t nist_p192_a = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_a_words};
bignum_t nist_p192_b = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_b_words};
bignum_t nist_p192_gx = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_gx_words};
bignum_t nist_p192_gy = {.bits = 187, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_gy_words};

// const ec_prime_curve ec_nist_p192 = {.p = &nist_p192_p, .a = &nist_p192_a, .b = &nist_p192_b, .gx = &nist_p192_gx, .gy = &nist_p192_gy};

uint32_t ec_prime_point_at_infinity(ec_point *a)
{
	if (a->x->bits == 0 && a->y->bits == 0)
	{
		return 1;
	}

	return 0;
}

ec_point *ec_prime_point_double(ec_group *eg, ec_point *r, ec_point *a)
{
	ec_prime_curve *parameters = eg->parameters;

	bignum_t *lambda = NULL;
	bignum_t *x = NULL, *y = NULL;

	if (r == NULL)
	{
		r = ec_point_new(eg);

		if (r == NULL)
		{
			return NULL;
		}
	}

	// If the point is at infinity O + O = O
	if (ec_prime_point_at_infinity(a))
	{
		ec_point_infinity(eg, r);
		return r;
	}

	// If the point is on the x-axis
	if (a->y->bits == 0)
	{
		ec_point_infinity(eg, r);
		return r;
	}

	bignum_ctx_start(eg->bctx, 3 * bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	lambda = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	x = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	y = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	// Compute lambda = (3(x^2) + A )/ 2y
	x = bignum_sqr(eg->bctx, x, a->x);
	x = bignum_lshift(x, x, 1);
	x = bignum_add(x, x, parameters->a);

	y = bignum_lshift(y, a->y, 1);
	y = bignum_modinv(eg->bctx, y, y, eg->p);

	lambda = bignum_modmul(eg->bctx, lambda, x, y, eg->p);

	// Compute x' = lambda^2 - 2x
	x = bignum_sqr(eg->bctx, x, lambda);
	y = bignum_lshift(y, a->x, 1);
	x = bignum_modsub(eg->bctx, x, x, y, eg->p);

	// Compute y' = lambda(x - x') - y
	y = bignum_sub(y, a->x, x);
	y = bignum_mul(eg->bctx, y, y, lambda);
	y = bignum_modsub(eg->bctx, y, y, a->y, eg->p);

	// Copy results
	bignum_copy(r->x, x);
	bignum_copy(r->y, y);

	bignum_ctx_end(eg->bctx);

	return r;
}

ec_point *ec_prime_point_add(ec_group *eg, ec_point *r, ec_point *a, ec_point *b)
{
	ec_prime_curve *parameters = eg->parameters;

	bignum_t *lambda = NULL;
	bignum_t *x = NULL, *y = NULL;

	if (r == NULL)
	{
		r = ec_point_new(eg);

		if (r == NULL)
		{
			return NULL;
		}
	}

	// If the point is at infinity O + O = O
	if (ec_prime_point_at_infinity(a) && ec_prime_point_at_infinity(b))
	{
		ec_point_infinity(eg, r);
		return r;
	}

	if (ec_prime_point_at_infinity(a))
	{
		ec_point_copy(r, b);
		return r;
	}

	if (ec_prime_point_at_infinity(b))
	{
		ec_point_copy(r, a);
		return r;
	}

	if (bignum_cmp(a->x, b->x) == 0)
	{
		// If the points are the same
		if (bignum_cmp(a->y, b->y) == 0)
		{
			ec_prime_point_double(eg, r, a);
			return r;
		}
		// If the points lie on the same ordinate line
		else
		{
			ec_point_infinity(eg, r);
			return r;
		}
	}

	bignum_ctx_start(eg->bctx, 3 * bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	lambda = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	x = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));
	y = bignum_ctx_allocate_bignum(eg->bctx, bignum_size(3 * ROUND_UP(eg->bits, BIGNUM_BITS_PER_WORD)));

	// Compute lambda = (y2 - y1)/ (x2 - x1)
	y = bignum_sub(y, b->y, a->y);
	x = bignum_sub(x, b->x, a->x);

	x = bignum_modinv(eg->bctx, x, x, eg->p);

	lambda = bignum_modmul(eg->bctx, lambda, y, x, eg->p);

	// Compute x' = lambda^2 - x1 - x2
	x = bignum_sqr(eg->bctx, x, lambda);
	x = bignum_sub(x, x, a->x);
	x = bignum_modsub(eg->bctx, x, x, b->x, eg->p);

	// Compute y' = lambda(x - x') - y
	y = bignum_sub(y, a->x, x);
	y = bignum_mul(eg->bctx, y, y, lambda);
	y = bignum_modsub(eg->bctx, y, y, a->y, eg->p);

	// Copy results
	bignum_copy(r->x, x);
	bignum_copy(r->y, y);

	bignum_ctx_end(eg->bctx);

	return r;
}

ec_point *ec_prime_point_multiply(ec_group *eg, ec_point *r, ec_point *a, bignum_t *n)
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

	ec_point_infinity(eg, r0);

	r1->x = x1;
	r1->y = y1;

	bignum_copy(x1, a->x);
	bignum_copy(y1, a->y);

	for (uint32_t i = 1; i < n->bits; ++i)
	{
		if (n->words[i / BIGNUM_BITS_PER_WORD] & ((bn_word_t)1 << (i % BIGNUM_BITS_PER_WORD)))
		{
			r0 = ec_prime_point_add(eg, r0, r0, r1);
			r1 = ec_prime_point_double(eg, r1, r1);
		}
		else
		{
			r1 = ec_prime_point_add(eg, r1, r0, r1);
			r0 = ec_prime_point_double(eg, r0, r0);
		}
	}

	ec_point_copy(r, r0);

	bignum_ctx_end(eg->bctx);

	return r;
}

uint32_t ec_prime_point_on_curve(ec_group *eg, ec_point *a)
{
	uint32_t result = 0;
	ec_prime_curve *parameters = eg->parameters;

	bignum_t *lhs = NULL;
	bignum_t *rhs = NULL;
	bignum_t *xcube = NULL;

	bignum_ctx_start(eg->bctx, bignum_size(eg->p->bits) + bignum_size(eg->p->bits * 2) + bignum_size(eg->p->bits * 3));

	lhs = bignum_ctx_allocate_bignum(eg->bctx, eg->p->bits);
	rhs = bignum_ctx_allocate_bignum(eg->bctx, eg->p->bits * 2);
	xcube = bignum_ctx_allocate_bignum(eg->bctx, eg->p->bits * 3);

	// Compute y^2 % p
	lhs = bignum_modsqr(eg->bctx, lhs, a->y, eg->p);

	// Compute Ax + B % p
	rhs = bignum_mul(eg->bctx, rhs, a->x, parameters->a);
	rhs = bignum_modadd(eg->bctx, rhs, rhs, parameters->b, eg->p);

	// Compute x^3 %p
	xcube = bignum_sqr(eg->bctx, xcube, a->x);
	xcube = bignum_modmul(eg->bctx, xcube, xcube, a->x, eg->p);

	rhs = bignum_modadd(eg->bctx, rhs, xcube, rhs, eg->p);

	// Compare
	if (bignum_cmp(lhs, rhs) == 0)
	{
		result = 1;
	}

	bignum_ctx_end(eg->bctx);

	return result;
}

uint32_t ec_prime_point_encode(struct _ec_group *eg, struct _ec_point *ep, void *buffer, uint32_t size, uint32_t compression)
{
	byte_t *out = buffer;
	uint32_t pos = 0;

	uint32_t bytes_for_point = ROUND_UP(eg->bits, 8);

	// Check for infinity
	if (ec_prime_point_at_infinity(ep))
	{
		if (size < 1)
		{
			return 0;
		}

		out[pos] = 0x00;
		pos += 1;

		return pos;
	}

	if (compression)
	{
		if (size < (1 + bytes_for_point))
		{
			return 0;
		}

		if (ep->y->words[0] % 2 == 0)
		{
			out[pos] = 0x02;
		}
		else
		{
			out[pos] = 0x03;
		}

		pos += 1;
		pos += bignum_get_bytes_be(ep->x, out + pos, bytes_for_point);
	}
	else
	{
		if (size < (1 + (2 * bytes_for_point)))
		{
			return 0;
		}

		out[pos] = 0x04;
		pos += 1;

		pos += bignum_get_bytes_be(ep->x, out + pos, bytes_for_point);
		pos += bignum_get_bytes_be(ep->y, out + pos, bytes_for_point);
	}

	return pos;
}

ec_point *ec_prime_point_decode(struct _ec_group *eg, struct _ec_point *ep, void *buffer, uint32_t size)
{
	ec_prime_curve *parameters = eg->parameters;
	byte_t *in = buffer;
	ec_point *p = ep;

	uint32_t bytes_for_point = ROUND_UP(eg->bits, 8);

	if (size < 1)
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

	// Check for infinity
	switch (in[0])
	{
	case 0x00:
	{
		ec_point_infinity(eg, ep);
		return ep;
	}
	case 0x02:
	case 0x03:
	{
		int32_t result = 0;

		bignum_t *temp = NULL, *ysq = NULL;
		bignum_t *y1 = NULL, *y2 = NULL;

		if (size < (1 + bytes_for_point))
		{
			return 0;
		}

		bignum_set_bytes_be(ep->x, PTR_OFFSET(buffer, 1), bytes_for_point);

		bignum_ctx_start(eg->bctx, bignum_size(eg->p->bits * 2) + bignum_size(eg->p->bits * 3) +
									   2 * bignum_size(eg->p->bits));

		temp = bignum_ctx_allocate_bignum(eg->bctx, eg->p->bits * 3);
		ysq = bignum_ctx_allocate_bignum(eg->bctx, eg->p->bits * 2);

		y1 = bignum_ctx_allocate_bignum(eg->bctx, eg->p->bits);
		y2 = bignum_ctx_allocate_bignum(eg->bctx, eg->p->bits);

		// Compute x^3 %p
		temp = bignum_sqr(eg->bctx, temp, ep->x);
		temp = bignum_modmul(eg->bctx, temp, temp, ep->x, eg->p);

		// Compute Ax + B % p
		ysq = bignum_mul(eg->bctx, ysq, ep->x, parameters->a);
		ysq = bignum_modadd(eg->bctx, ysq, ysq, parameters->b, eg->p);

		ysq = bignum_modadd(eg->bctx, ysq, temp, ysq, eg->p);

		// Find sqrt
		result = bignum_modsqrt(eg->bctx, y1, y2, ysq, eg->p);

		if (result == -1)
		{
			if (p == NULL)
			{
				ec_point_delete(ep);
			}

			bignum_ctx_end(eg->bctx);
			return NULL;
		}

		if (in[0] == 0x02)
		{
			if (y1->words[0] % 2 == 0)
			{
				bignum_copy(ep->y, y1);
			}
			else
			{
				bignum_copy(ep->y, y2);
			}
		}
		else
		{
			if (y1->words[0] % 2 == 0)
			{
				bignum_copy(ep->y, y2);
			}
			else
			{
				bignum_copy(ep->y, y1);
			}
		}

		bignum_ctx_end(eg->bctx);

		return ep;
	}
	case 0x04:
	{
		if (size < (1 + (2 * bytes_for_point)))
		{
			return 0;
		}

		bignum_set_bytes_be(ep->x, PTR_OFFSET(buffer, 1), bytes_for_point);
		bignum_set_bytes_be(ep->y, PTR_OFFSET(buffer, 1 + bytes_for_point), bytes_for_point);

		return ep;
	}

	default:
		return NULL;
	}
}
