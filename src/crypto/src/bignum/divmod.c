/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>
#include <bignum-internal.h>

#include <string.h>

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
			bignum_copy(r, dd);
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

	bignum_t *quotient = NULL;
	bignum_t *remainder = NULL;

	bignum_ctx *obctx = bctx;

	if (quotient_sign < 0)
	{
		++quotient_bits;
	}

	r = bignum_resize(r, quotient_bits);

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

	bignum_ctx_start(bctx, bignum_size(remainder_bits) + bignum_size(quotient_bits));

	quotient = bignum_ctx_allocate_bignum(bctx, quotient_bits);
	remainder = bignum_ctx_allocate_bignum(bctx, remainder_bits);

	status = bignum_divmod(bctx, a, b, quotient, remainder);

	bignum_copy(r, quotient);

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
	bignum_t *remainder = NULL;

	bignum_ctx *obctx = bctx;

	if (quotient_sign < 0)
	{
		++quotient_bits;
	}

	r = bignum_resize(r, remainder_bits);

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

	bignum_ctx_start(bctx, bignum_size(remainder_bits) + bignum_size(quotient_bits));

	quotient = bignum_ctx_allocate_bignum(bctx, quotient_bits);
	remainder = bignum_ctx_allocate_bignum(bctx, remainder_bits);

	status = bignum_divmod(bctx, a, b, quotient, remainder);

	bignum_copy(r, remainder);

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
	void *dv_copy1 = NULL, *dv_copy2 = NULL;

	uint32_t dd_words = BIGNUM_WORD_COUNT(dd);
	uint32_t dv_words = BIGNUM_WORD_COUNT(dv);
	uint32_t mu_words = BIGNUM_WORD_COUNT(mu);

	uint32_t q1_words = dd_words - (dv_words - 1);
	uint32_t q2_words = q1_words + mu_words + 1;
	uint32_t qt_words = q2_words - (dv_words + 1);

	uint32_t r2_words = qt_words + dv_words + 1;
	uint32_t rt_words = dv_words + 1;

	// Divisor is greater than dividend
	if (dv->bits > dd->bits)
	{
		bignum_zero(q);
		bignum_copy(r, dd);

		return 0;
	}

	bignum_ctx_start(bctx, (q2_words + (2 * r2_words) + (2 * rt_words)) * BIGNUM_WORD_SIZE);

	q2 = bignum_ctx_allocate_raw(bctx, q2_words * BIGNUM_WORD_SIZE);
	r1 = bignum_ctx_allocate_raw(bctx, r2_words * BIGNUM_WORD_SIZE);
	r2 = bignum_ctx_allocate_raw(bctx, r2_words * BIGNUM_WORD_SIZE);
	dv_copy1 = bignum_ctx_allocate_raw(bctx, rt_words * BIGNUM_WORD_SIZE);
	dv_copy2 = bignum_ctx_allocate_raw(bctx, rt_words * BIGNUM_WORD_SIZE);

	memset(q2, 0, q2_words * BIGNUM_WORD_SIZE);
	memset(r1, 0, r2_words * BIGNUM_WORD_SIZE);
	memset(r2, 0, r2_words * BIGNUM_WORD_SIZE);
	memset(dv_copy1, 0, rt_words * BIGNUM_WORD_SIZE);
	memset(dv_copy2, 0, rt_words * BIGNUM_WORD_SIZE);

	// TODO: Partial multiplications

	// q1 = dd / 2^(words - 1)
	q1 = dd->words + (dv_words - 1);

	// q2 = q1 * mu
	bignum_mul_words(q2, q1, mu->words, q1_words, mu_words);

	// q = q2 / 2^(words + 1)
	qt = (bn_word_t *)q2 + (dv_words + 1);

	// r1 / dd % 2^(words + 1)
	memcpy(r1, dd->words, MIN(dd_words, dv_words + 1) * BIGNUM_WORD_SIZE);

	// r2 = (qt*dv) % 2^(words + 1)
	bignum_mul_words(r2, qt, dv->words, qt_words, dv_words);
	memset((bn_word_t *)r2 + rt_words, 0, (qt_words + dv_words - rt_words) * BIGNUM_WORD_SIZE);

	// rt = r1 - r2
	rt = r2;
	bignum_sub_words(rt, r1, r2, rt_words);

	// Create copy of the divisor for easier subraction.
	memcpy(dv_copy1, dv->words, dv_words * BIGNUM_WORD_SIZE);
	memcpy(dv_copy2, dv->words, dv_words * BIGNUM_WORD_SIZE);

	while (bignum_cmp_words(rt, dv_copy2, rt_words) >= 0)
	{
		// (q,r) = (q + 1,r − dv)
		bignum_sub_words(rt, rt, dv_copy1, rt_words);
		bignum_increment(qt, qt_words);
	}

	memcpy(q->words, qt, CEIL_DIV(quotient_bits, BIGNUM_BITS_PER_WORD) * BIGNUM_WORD_SIZE);
	q->bits = bignum_bitcount(q);

	memcpy(r->words, rt, CEIL_DIV(remainder_bits, BIGNUM_BITS_PER_WORD) * BIGNUM_WORD_SIZE);
	r->bits = bignum_bitcount(r);

	bignum_ctx_end(bctx);

	return 0;
}

bignum_t *bignum_umod2p(bignum_t *a, uint32_t bits)
{
	uint32_t words_cleared = 0;
	uint32_t top_word = 0;

	if (bits > a->bits)
	{
		return a;
	}

	top_word = CEIL_DIV(bits, BIGNUM_BITS_PER_WORD);
	words_cleared = BIGNUM_WORD_COUNT(a) - top_word;

	// Clear whole words
	if (words_cleared > 0)
	{
		memset(a->words + top_word, 0, words_cleared * BIGNUM_WORD_SIZE);
	}

	// Clear remaining bits
	if (bits % BIGNUM_BITS_PER_WORD != 0)
	{
		a->words[top_word - 1] &= ((1ull << bits) - 1);
	}

	a->bits = bignum_bitcount(a);

	return a;
}
