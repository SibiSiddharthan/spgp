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

uint8_t bignum_sub_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count);
int32_t bignum_usub(bignum_t *r, bignum_t *a, bignum_t *b, uint32_t min_words, uint32_t total_words);
void bignum_2complement(bn_word_t *r, uint32_t count);

static uint32_t count_trailing_zeros(bignum_t *bn)
{
	uint32_t count = bn->size / BIGNUM_WORD_SIZE;

	for (uint32_t i = 0; i < count; ++i)
	{
		if (bn->words[i] == 0)
		{
			continue;
		}

		return (i * BIGNUM_BITS_PER_WORD) + bsf_64(bn->words[i]);
	}

	return count * BIGNUM_BITS_PER_WORD;
}

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

bignum_t *binary_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
	bignum_t *a_temp, *b_temp = NULL;
	size_t a_size = bignum_size(a->bits);
	size_t b_size = bignum_size(b->bits);
	uint32_t a_shift = 0, b_shift = 0, min_shift = 0;

	bignum_ctx *obctx = bctx;
	size_t ctx_size = a_size + b_size;

	r = bignum_resize(r, MIN(a->bits, b->bits));

	if (r == NULL)
	{
		return NULL;
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

	// Set gcd to 1
	bignum_one(r);

	a_temp = bignum_ctx_allocate_bignum(bctx, a->bits);
	b_temp = bignum_ctx_allocate_bignum(bctx, b->bits);

	a_shift = count_trailing_zeros(a);
	b_shift = count_trailing_zeros(b);

	min_shift = MIN(a_shift, b_shift);

	a_temp = bignum_rshift(a_temp, a, a_shift);
	b_temp = bignum_rshift(b_temp, b, b_shift);

	a_temp->sign = b_temp->sign = 1;

	// Multiply gcd with common powers of 2 of a and b.
	r = bignum_lshift(r, r, min_shift);

	while (1)
	{
		bignum_t *temp = NULL;

		// Both a,b should be odd now.
		if (a_temp->bits > b_temp->bits)
		{
			bignum_usub(a_temp, a_temp, b_temp, BIGNUM_WORD_COUNT(b_temp), BIGNUM_WORD_COUNT(a_temp));
			temp = a_temp;
		}
		else if (a_temp->bits < b_temp->bits)
		{
			bignum_usub(b_temp, b_temp, a_temp, BIGNUM_WORD_COUNT(a_temp), BIGNUM_WORD_COUNT(b_temp));
			temp = b_temp;
		}
		else // a_temp->bits == b_temp->bits
		{
			uint8_t borrow = bignum_sub_words(a_temp->words, a_temp->words, b_temp->words, BIGNUM_WORD_COUNT(a_temp));
			temp = a_temp;

			if (borrow)
			{
				// b>a, Since we did (a-b) change it to (b-a).
				bignum_2complement(a_temp->words, BIGNUM_WORD_COUNT(a_temp));

				a_temp = b_temp;
				b_temp = temp;
				temp = b_temp;
			}
		}

		// Set the bits for the next iteration.
		bignum_bitcount(a_temp);
		bignum_bitcount(b_temp);

		// Now temp should be even
		if (temp->bits == 0)
		{
			// We are done. r*(not temp) is the gcd.
			r = bignum_mul(r, r, temp == a_temp ? b_temp : a_temp);
			return r;
		}

		temp = bignum_rshift(temp, temp, count_trailing_zeros(temp));
	}

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}
}

bignum_t *bignum_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
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

	// Single word gcd
	if (a->bits <= BIGNUM_BITS_PER_WORD && b->bits <= BIGNUM_BITS_PER_WORD)
	{
		bn_word_t gcd;

		gcd = euclid_gcd(a->words[0], b->words[0]);
		bignum_set_word(r, gcd);
		r->sign = 1;

		return r;
	}

	return binary_gcd(bctx, r, a, b);
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

int32_t bignum_gcdex(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b)
{
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

	// Single word gcd
	if (a->bits <= (BIGNUM_BITS_PER_WORD / 2) && b->bits <= (BIGNUM_BITS_PER_WORD / 2))
	{
		bn_word_t gcd;
		int64_t uw, vw;

		gcd = euclid_gcdex(&uw, &vw, a->words[0], b->words[0]);
		bignum_set_word(r, gcd);
		r->sign = 1;

		if (uw < 0)
		{
			bignum_set_word(u, ~uw + 1);
			u->sign = -1;
		}
		else
		{
			bignum_set_word(u, uw);
			u->sign = 1;
		}

		if (vw < 0)
		{
			bignum_set_word(v, ~vw + 1);
			v->sign = -1;
		}
		else
		{
			bignum_set_word(v, vw);
			v->sign = 1;
		}

		return 0;
	}

	return 0;
}