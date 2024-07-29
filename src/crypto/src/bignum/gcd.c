/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <bitscan.h>
#include <round.h>
#include <minmax.h>

#include <bignum-internal.h>

bn_word_t euclid_gcd(bn_word_t a, bn_word_t b)
{
	bn_word_t r;

	// Make sure a > b
	if (a < b)
	{
		r = a;
		a = b;
		b = r;
	}

	while ((r = a % b) != 0)
	{
		a = b;
		b = r;
	}

	r = b;

	return r;
}

bn_word_t euclid_gcdex(int64_t *u, int64_t *v, bn_word_t a, bn_word_t b)
{
	bn_word_t r;
	bn_word_t q;
	int64_t t, tu, tv;

	// Make sure a > b
	if (a < b)
	{
		r = a;
		a = b;
		b = r;
	}

	tu = 0;
	tv = 1;

	while (b != 0)
	{
		q = a / b;
		r = a % b;

		a = b;
		b = r;

		t = tu;
		tu = tv;
		tv = t - q * (tv);
	}

	r = a;
	*u = tu;
	*v = tv;

	return r;
}

bignum_t *binary_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
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
		bignum_bitcount(a);
		bignum_bitcount(b);

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

int32_t binary_gcdex(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b)
{
	bignum_t *a_temp = NULL, *b_temp = NULL;
	bignum_t *x = NULL, *y = NULL;
	size_t a_size = bignum_size(a->bits);
	size_t b_size = bignum_size(b->bits);
	uint32_t a_shift = 0, b_shift = 0, min_shift = 0;
	uint32_t max_bits = MAX(a->bits, b->bits);

	bignum_ctx *obctx = bctx;
	size_t ctx_size = a_size + b_size;

	r = bignum_resize(r, MIN(a->bits, b->bits));
	u = bignum_resize(r, a->bits);
	v = bignum_resize(r, b->bits);

	if (r == NULL || u == NULL || v == NULL)
	{
		return -1;
	}

	if (obctx == NULL)
	{
		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return -1;
		}
	}

	bignum_ctx_start(bctx, ctx_size);

	a_temp = bignum_ctx_allocate_bignum(bctx, a->bits);
	b_temp = bignum_ctx_allocate_bignum(bctx, b->bits);
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

	a_temp = bignum_rshift(a_temp, a, min_shift);
	b_temp = bignum_rshift(b_temp, b, min_shift);

	a_temp->sign = b_temp->sign = 1;

	// Multiply gcd with common powers of 2 of a and b.
	r = bignum_lshift(r, r, min_shift);

	while (a_temp->bits > 0)
	{
		while (a_temp->words[0] % 2 == 0)
		{
			a_temp = bignum_rshift(a_temp, a_temp, 1);

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

		while (b_temp->words[0] % 2 == 0)
		{
			b_temp = bignum_rshift(b_temp, b_temp, 1);

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
		if (bignum_cmp(a_temp, b_temp) >= 0)
		{
			a_temp = bignum_sub(a_temp, a_temp, b_temp);
			x = bignum_sub(x, x, u);
			y = bignum_sub(y, y, v);
		}
		else
		{
			b_temp = bignum_sub(b_temp, b_temp, a_temp);
			u = bignum_sub(u, u, x);
			v = bignum_sub(v, v, y);
		}
	}

	r = bignum_mul(bctx, r, r, b_temp);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return 0;
}

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
		bignum_copy(r, sizeof(bignum_t) + r->size, (bignum_cmp_abs(a, b) > 0) ? a : b);
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
	int32_t status = 0;

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
			bignum_copy(r, sizeof(bignum_t) + r->size, a);
			bignum_zero(v);
			bignum_one(u);
		}
		else if (cmp < 0)
		{
			bignum_copy(r, sizeof(bignum_t) + r->size, b);
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

	status = binary_gcdex(bctx, r, u, v, a, b);

	return status;
}
