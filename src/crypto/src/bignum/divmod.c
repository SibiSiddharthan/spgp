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

int32_t bignum_divmod(bignum_ctx *bctx, bignum_t *dd, bignum_t *dv, bignum_t *q, bignum_t *r)
{
	void *scratch = NULL;
	size_t required_scratch_size = 0;

	uint32_t quotient_bits = ((dd->bits >= dv->bits) ? (dd->bits - dv->bits + 1) : 1) + BIGNUM_BITS_PER_WORD;
	uint32_t remainder_bits = dv->bits;
	int32_t quotient_sign = dd->sign * dv->sign;

	// Zero divisor, error.
	if (dv->bits == 0)
	{
		return -1;
	}

	if (quotient_sign < 0)
	{
		++quotient_bits;
	}

	q = bignum_resize(q, quotient_bits);
	r = bignum_resize(r, remainder_bits);

	if (q == NULL || r == NULL)
	{
		return -1;
	}

	// Zero dividend
	if (dd->bits == 0)
	{
		bignum_zero(q);
		bignum_zero(r);

		goto finalize;
	}

	// Divisor is greater than dividend
	if (dv->bits > dd->bits)
	{
		if (quotient_sign > 0)
		{
			bignum_zero(q);
			bignum_copy(r, sizeof(bignum_t) + r->size, dd);
		}
		else
		{
			q->words[0] = 1;
			q->sign = -1;
			q->bits = 1;

			bignum_usub(r, dv, dd, BIGNUM_WORD_COUNT(dd), BIGNUM_WORD_COUNT(dv));

			r->sign = dv->sign;
			r->bits = bignum_bitcount(r);
		}

		goto finalize;
	}

	// General case long division.
	// For normalized dividend, normalized divsor, multiplication scratch.
	required_scratch_size = (CEIL_DIV(dd->bits, BIGNUM_BITS_PER_WORD) + 1) * sizeof(bn_word_t) * 3;

	bignum_ctx_start(bctx, required_scratch_size);

	scratch = bignum_ctx_allocate_raw(bctx, required_scratch_size);
	memset(scratch, 0, required_scratch_size);

	bignum_div_words(scratch, dd->words, dv->words, q->words, r->words, BIGNUM_WORD_COUNT(dd), BIGNUM_WORD_COUNT(dv));

	// The sign of the remainder will be same as that of the divisor.
	q->sign = quotient_sign;
	r->sign = dv->sign;

	if (bignum_bitcount(r) != 0)
	{
		if (quotient_sign < 0)
		{
			// Increase quotient by 1.
			bignum_increment(q->words, CEIL_DIV(quotient_bits, BIGNUM_BITS_PER_WORD));

			// Subract divisor from remainder and take 2's complement.
			bignum_sub_words(r->words, r->words, dv->words, CEIL_DIV(remainder_bits, BIGNUM_BITS_PER_WORD));
			bignum_2complement(r->words, CEIL_DIV(remainder_bits, BIGNUM_BITS_PER_WORD));
		}
	}

	q->bits = bignum_bitcount(q);
	r->bits = bignum_bitcount(r);

	bignum_ctx_end(bctx);

finalize:
	return 0;
}

bignum_t *bignum_div(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
	int32_t status;

	uint32_t quotient_bits = ((a->bits >= b->bits) ? (a->bits - b->bits + 1) : 1) + BIGNUM_BITS_PER_WORD;
	uint32_t remainder_bits = b->bits;
	int32_t quotient_sign = a->sign * b->sign;

	bignum_t *quotient = r;
	bignum_t *remainder = NULL;

	bignum_ctx *obctx = bctx;

	if (quotient_sign < 0)
	{
		++quotient_bits;
	}

	quotient = bignum_resize(quotient, quotient_bits);

	if (quotient == NULL)
	{
		return NULL;
	}

	if (obctx == NULL)
	{
		size_t ctx_size = 0;

		ctx_size += bignum_size(remainder_bits);
		ctx_size += (CEIL_DIV(a->bits, BIGNUM_BITS_PER_WORD) + 1) * sizeof(bn_word_t) * 3;

		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, bignum_size(remainder_bits));

	remainder = bignum_ctx_allocate_bignum(bctx, remainder_bits);
	status = bignum_divmod(bctx, a, b, quotient, remainder);

	bignum_ctx_end(bctx);

	if (status == -1)
	{
		return NULL;
	}

	return r;
}

bignum_t *bignum_mod(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
	int32_t status;

	uint32_t quotient_bits = ((a->bits >= b->bits) ? (a->bits - b->bits + 1) : 1) + BIGNUM_BITS_PER_WORD;
	uint32_t remainder_bits = b->bits;
	int32_t quotient_sign = a->sign * b->sign;

	bignum_t *quotient = NULL;
	bignum_t *remainder = r;

	bignum_ctx *obctx = bctx;

	if (quotient_sign < 0)
	{
		++quotient_bits;
	}

	remainder = bignum_resize(remainder, remainder_bits);

	if (remainder == NULL)
	{
		return NULL;
	}

	if (obctx == NULL)
	{
		size_t ctx_size = 0;

		ctx_size += bignum_size(quotient_bits);
		ctx_size += (CEIL_DIV(a->bits, BIGNUM_BITS_PER_WORD) + 1) * sizeof(bn_word_t) * 3;

		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, bignum_size(quotient_bits));

	quotient = bignum_ctx_allocate_bignum(bctx, quotient_bits);
	status = bignum_divmod(bctx, a, b, quotient, remainder);

	bignum_ctx_end(bctx);

	if (status == -1)
	{
		return NULL;
	}

	return r;
}

int32_t bignum_barret_udivmod(bignum_ctx *bctx, bignum_t *dd, bignum_t *dv, bignum_t *mu, bignum_t *q, bignum_t *r)
{
	uint32_t quotient_bits = ((dd->bits >= dv->bits) ? (dd->bits - dv->bits + 1) : 1) + BIGNUM_BITS_PER_WORD;
	uint32_t remainder_bits = dv->bits;

	void *q1 = NULL, *q2 = NULL, *qt = NULL;
	void *r1 = NULL, *r2 = NULL, *rt = NULL;
	void *dv_copy = NULL;

	uint32_t dd_words = BIGNUM_WORD_COUNT(dv);
	uint32_t dv_words = BIGNUM_WORD_COUNT(dv);
	uint32_t mu_words = BIGNUM_WORD_COUNT(mu);

	uint32_t q1_words = dd_words - (dv_words - 1);
	uint32_t q2_words = q1_words + mu_words;
	uint32_t qt_words = q2_words - (dv_words + 1);

	uint32_t r2_words = qt_words + dv_words;
	uint32_t rt_words = dv_words + 1;

	// Divisor is greater than dividend
	if (dv->bits > dd->bits)
	{
		bignum_zero(q);
		bignum_copy(r, sizeof(bignum_t) + r->size, dd);

		return 0;
	}

	bignum_ctx_start(bctx, (q1_words + r2_words + rt_words) * BIGNUM_WORD_SIZE);

	q2 = bignum_ctx_allocate_raw(bctx, q1_words * BIGNUM_WORD_SIZE);
	r2 = bignum_ctx_allocate_bignum(bctx, r2_words * BIGNUM_WORD_SIZE);
	dv_copy = bignum_ctx_allocate_bignum(bctx, rt_words * BIGNUM_WORD_SIZE);

	// TODO: Partial multiplications

	// q1 = dd / 2^(words - 1)
	q1 = dd->words + (dv_words - 1);

	// q2 = q1 * mu
	bignum_mul_words(q2, q1, mu->words, q1_words, mu_words);

	// q = q2 / 2^(words + 1)
	qt = (bn_word_t *)q2 + (dv_words + 1);

	// r1 / dd % 2^(words + 1)
	r1 = dd->words;

	// r2 = (qt*dv) % 2^(words + 1)
	bignum_mul_words(r2, qt, dv->words, qt_words, dv_words);

	// rt = r1 - r2
	rt = r2;
	bignum_sub_words(rt, r1, r2, rt_words);

	// Create copy of the divisor for easier subraction.
	memcpy(dv_copy, dv->words, dv_words);

	while (bignum_cmp_words(rt, dv->words, rt_words) >= 0)
	{
		// (q,r) = (q + 1,r − dv)
		bignum_sub_words(rt, rt, dv_copy, rt_words);
		bignum_increment(qt, qt_words);
	}

	memcpy(q->words, qt, CEIL_DIV(quotient_bits, BIGNUM_BITS_PER_WORD));
	q->bits = bignum_bitcount(q);

	memcpy(r->words, rt, CEIL_DIV(remainder_bits, BIGNUM_BITS_PER_WORD));
	r->bits = bignum_bitcount(r);

	bignum_ctx_end(bctx);

	return 0;
}
