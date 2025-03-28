/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>
#include <bitscan.h>

#include <string.h>

#include <bignum-internal.h>

static bignum_t *euclid_gcd(bignum_ctx *bctx, bignum_t *gcd, bignum_t *a, bignum_t *b)
{
	bignum_t *q = NULL, *r = NULL;

	bignum_ctx_start(bctx, 0);

	// Make sure a > b
	if (bignum_cmp_abs(a, b) < 0)
	{
		bignum_t *t;

		t = a;
		a = b;
		b = t;
	}

	a = bignum_dup(bctx, a);
	b = bignum_dup(bctx, b);
	q = bignum_ctx_allocate_bignum(bctx, a->bits);
	r = bignum_ctx_allocate_bignum(bctx, a->bits);

	a->sign = b->sign = q->sign = r->sign = 1;

	do
	{
		bignum_divmod(bctx, a, b, q, r);

		bignum_copy(a, b);
		bignum_copy(b, r);

	} while (r->bits > 0);

	gcd = bignum_copy(gcd, a);
	gcd->sign = 1;

	bignum_ctx_end(bctx);

	return r;
}

static bignum_t *euclid_gcdex(bignum_ctx *bctx, bignum_t *gcd, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b)
{
	bignum_t *q = NULL, *r = NULL;
	bignum_t *t1 = NULL, *t2 = NULL;
	bignum_t *u1 = NULL, *u2 = NULL, *u3 = NULL;
	bignum_t *v1 = NULL, *v2 = NULL, *v3 = NULL;

	uint32_t max_bits = MAX(a->bits, b->bits) * 2;

	bignum_ctx_start(bctx, 10 * bignum_size(max_bits));

	q = bignum_ctx_allocate_bignum(bctx, max_bits);
	r = bignum_ctx_allocate_bignum(bctx, max_bits);

	u1 = bignum_ctx_allocate_bignum(bctx, max_bits);
	u2 = bignum_ctx_allocate_bignum(bctx, max_bits);
	u3 = bignum_ctx_allocate_bignum(bctx, max_bits);

	v1 = bignum_ctx_allocate_bignum(bctx, max_bits);
	v2 = bignum_ctx_allocate_bignum(bctx, max_bits);
	v3 = bignum_ctx_allocate_bignum(bctx, max_bits);

	t1 = bignum_ctx_allocate_bignum(bctx, max_bits);
	t2 = bignum_ctx_allocate_bignum(bctx, max_bits);

	a->sign = b->sign = 1;

	// Make sure a > b
	if (bignum_cmp_abs(a, b) < 0)
	{
		bignum_t *t;

		t = a;
		a = b;
		b = t;

		t = u;
		u = v;
		v = t;
	}

	// Initial values.
	bignum_one(u1);
	bignum_zero(v1);

	bignum_zero(u2);
	bignum_one(v2);

	u3 = bignum_dup(bctx, a);
	v3 = bignum_dup(bctx, b);

	do
	{
		bignum_divmod(bctx, u3, v3, q, r);

		bignum_copy(u3, v3);
		bignum_copy(v3, r);

		t1 = bignum_mul(bctx, t1, v1, q);
		t1 = bignum_sub(t1, u1, t1);

		t2 = bignum_mul(bctx, t2, v2, q);
		t2 = bignum_sub(t2, u2, t2);

		bignum_copy(u1, v1);
		bignum_copy(u2, v2);

		bignum_copy(v1, t1);
		bignum_copy(v2, t2);

	} while (r->bits > 0);

	gcd = bignum_copy(gcd, u3);
	gcd->sign = 1;

	u = bignum_copy(u, u1);
	v = bignum_copy(v, u2);

	bignum_ctx_end(bctx);

	return gcd;
}

static bignum_t *binary_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
	size_t a_size = bignum_size(a->bits);
	size_t b_size = bignum_size(b->bits);
	uint32_t a_shift = 0, b_shift = 0, min_shift = 0;

	size_t ctx_size = a_size + b_size;

	bignum_ctx_start(bctx, ctx_size);

	a = bignum_dup(bctx, a);
	b = bignum_dup(bctx, b);

	// Set gcd to 1
	bignum_one(r);

	a_shift = bignum_ctz(a);
	b_shift = bignum_ctz(b);

	min_shift = MIN(a_shift, b_shift);

	a = bignum_rshift(a, a, a_shift);
	b = bignum_rshift(b, b, b_shift);

	a->sign = b->sign = 1;

	// Multiply gcd with common powers of 2 of a and b.
	r = bignum_lshift(r, r, min_shift);

	while (1)
	{
		bignum_t *temp = NULL;

		// Both a,b should be odd now.
		if (a->bits > b->bits)
		{
			bignum_usub(a, a, b, BIGNUM_WORD_COUNT(b), BIGNUM_WORD_COUNT(a));
			temp = a;
		}
		else if (a->bits < b->bits)
		{
			bignum_usub(b, b, a, BIGNUM_WORD_COUNT(a), BIGNUM_WORD_COUNT(b));
			temp = b;
		}
		else // a_temp->bits == b_temp->bits
		{
			uint8_t borrow = bignum_sub_words(a->words, a->words, b->words, BIGNUM_WORD_COUNT(a));
			temp = a;

			if (borrow)
			{
				// b>a, Since we did (a-b) change it to (b-a).
				bignum_2complement(a->words, BIGNUM_WORD_COUNT(a));

				a = b;
				b = temp;
				temp = b;
			}
		}

		// Set the bits for the next iteration.
		a->bits = bignum_bitcount(a);
		b->bits = bignum_bitcount(b);

		// Now temp should be even
		if (temp->bits == 0)
		{
			// We are done. r*(not temp) is the gcd.
			r = bignum_mul(bctx, r, r, temp == a ? b : a);
			break;
		}

		temp = bignum_rshift(temp, temp, bignum_ctz(temp));
	}

	bignum_ctx_end(bctx);

	return r;
}

static bignum_t *binary_gcdex(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b)
{
	bignum_t *x = NULL, *y = NULL;
	uint32_t a_shift = 0, b_shift = 0, min_shift = 0;
	uint32_t max_bits = MAX(a->bits, b->bits);

	bignum_ctx_start(bctx, 0);

	a = bignum_dup(bctx, a);
	b = bignum_dup(bctx, b);
	x = bignum_ctx_allocate_bignum(bctx, max_bits);
	y = bignum_ctx_allocate_bignum(bctx, max_bits);

	// Set gcd to 1
	bignum_one(r);

	// Initial values.
	bignum_one(x);
	bignum_zero(y);

	bignum_zero(u);
	bignum_one(v);

	a_shift = bignum_ctz(a);
	b_shift = bignum_ctz(b);

	min_shift = MIN(a_shift, b_shift);

	a = bignum_rshift(a, a, min_shift);
	b = bignum_rshift(b, b, min_shift);

	a->sign = b->sign = 1;

	// Multiply gcd with common powers of 2 of a and b.
	r = bignum_lshift(r, r, min_shift);

	while (a->bits > 0)
	{
		while (a->words[0] % 2 == 0)
		{
			a = bignum_rshift(a, a, 1);

			if ((x->words[0] % 2 == 0) && (y->words[0] % 2 == 0))
			{
				x = bignum_rshift(x, x, 1);
				y = bignum_rshift(x, x, 1);
			}
			else
			{
				x = bignum_add(x, x, b);
				x = bignum_rshift(x, x, 1);

				y = bignum_sub(y, y, a);
				y = bignum_rshift(y, y, 1);
			}
		}

		while (b->words[0] % 2 == 0)
		{
			b = bignum_rshift(b, b, 1);

			if ((u->words[0] % 2 == 0) && (v->words[0] % 2 == 0))
			{
				u = bignum_rshift(u, u, 1);
				v = bignum_rshift(v, v, 1);
			}
			else
			{
				u = bignum_add(u, u, b);
				u = bignum_rshift(u, u, 1);

				v = bignum_sub(v, v, a);
				v = bignum_rshift(v, v, 1);
			}
		}

		// Both a,b should be odd now.
		if (bignum_cmp(a, b) >= 0)
		{
			a = bignum_sub(a, a, b);
			x = bignum_sub(x, x, u);
			y = bignum_sub(y, y, v);
		}
		else
		{
			b = bignum_sub(b, b, a);
			u = bignum_sub(u, u, x);
			v = bignum_sub(v, v, y);
		}
	}

	r = bignum_mul(bctx, r, r, b);

	bignum_ctx_end(bctx);

	return r;
}

static bignum_t *bignum_gcd_common(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b,
								   bignum_t *(*gcd_algorithm)(bignum_ctx *, bignum_t *, bignum_t *, bignum_t *))

{
	bignum_ctx *obctx = bctx;

	// Handle zero
	if (a->bits == 0 || b->bits == 0)
	{
		r = bignum_resize(r, MAX(a->bits, b->bits));

		if (r == NULL)
		{
			return NULL;
		}

		// GCD is always positive.
		bignum_copy(r, (bignum_cmp_abs(a, b) > 0) ? a : b);
		r->sign = 1;

		return r;
	}

	// General case.
	r = bignum_resize(r, MIN(a->bits, b->bits));

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

	gcd_algorithm(bctx, r, a, b);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}

static int32_t bignum_gcdex_common(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b,
								   bignum_t *(*gcdex_algorithm)(bignum_ctx *, bignum_t *, bignum_t *, bignum_t *, bignum_t *, bignum_t *))
{
	bignum_ctx *obctx = bctx;

	// Handle zero
	if (a->bits == 0 || b->bits == 0)
	{
		r = bignum_resize(r, MAX(a->bits, b->bits));

		if (r == NULL)
		{
			return -1;
		}

		int32_t cmp = bignum_cmp_abs(a, b);

		if (cmp > 0)
		{
			bignum_copy(r, a);
			bignum_zero(v);
			bignum_one(u);
		}
		else if (cmp < 0)
		{
			bignum_copy(r, b);
			bignum_zero(u);
			bignum_one(v);
		}
		else
		{
			bignum_zero(r);
			bignum_zero(u);
			bignum_zero(v);
		}

		// GCD is always positive.
		r->sign = 1;

		return 0;
	}

	// General case.
	r = bignum_resize(r, MIN(a->bits, b->bits));
	u = bignum_resize(u, a->bits);
	v = bignum_resize(v, b->bits);

	if (r == NULL || u == NULL || v == NULL)
	{
		return -1;
	}

	if (obctx == NULL)
	{
		bctx = bignum_ctx_new(0);

		if (bctx == NULL)
		{
			return -1;
		}
	}

	r = gcdex_algorithm(bctx, r, u, v, a, b);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return 0;
}

bignum_t *bignum_euclid_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
	return bignum_gcd_common(bctx, r, a, b, euclid_gcd);
};

int32_t bignum_euclid_gcdex(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b)
{
	return bignum_gcdex_common(bctx, r, u, v, a, b, euclid_gcdex);
};

bignum_t *bignum_binary_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
	return bignum_gcd_common(bctx, r, a, b, binary_gcd);
};

int32_t bignum_binary_gcdex(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b)
{
	return bignum_gcdex_common(bctx, r, u, v, a, b, binary_gcdex);
};

bignum_t *bignum_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
	bignum_ctx *obctx = bctx;

	// Handle zero
	if (a->bits == 0 || b->bits == 0)
	{
		r = bignum_resize(r, MAX(a->bits, b->bits));

		if (r == NULL)
		{
			return NULL;
		}

		// GCD is always positive.
		bignum_copy(r, (bignum_cmp_abs(a, b) > 0) ? a : b);
		r->sign = 1;

		return r;
	}

	// General case.
	r = bignum_resize(r, MIN(a->bits, b->bits));

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

	binary_gcd(bctx, r, a, b);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}

int32_t bignum_gcdex(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b)
{
	bignum_ctx *obctx = bctx;

	// Handle zero
	if (a->bits == 0 || b->bits == 0)
	{
		r = bignum_resize(r, MAX(a->bits, b->bits));

		if (r == NULL)
		{
			return -1;
		}

		int32_t cmp = bignum_cmp_abs(a, b);

		if (cmp > 0)
		{
			bignum_copy(r, a);
			bignum_zero(v);
			bignum_one(u);
		}
		else if (cmp < 0)
		{
			bignum_copy(r, b);
			bignum_zero(u);
			bignum_one(v);
		}
		else
		{
			bignum_zero(r);
			bignum_zero(u);
			bignum_zero(v);
		}

		// GCD is always positive.
		r->sign = 1;

		return 0;
	}

	// General case.
	r = bignum_resize(r, MIN(a->bits, b->bits));
	u = bignum_resize(u, a->bits);
	v = bignum_resize(v, b->bits);

	if (r == NULL || u == NULL || v == NULL)
	{
		return -1;
	}

	if (obctx == NULL)
	{
		bctx = bignum_ctx_new(0);

		if (bctx == NULL)
		{
			return -1;
		}
	}

	r = binary_gcdex(bctx, r, u, v, a, b);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return 0;
}
