/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <bignum.h>
#include <round.h>

void bignum_increment(bn_word_t *r, uint32_t count);
void bignum_2complement(bn_word_t *r, uint32_t count);
void bignum_div_words(void *scratch, bn_word_t *dd, bn_word_t *dv, bn_word_t *q, bn_word_t *r, uint32_t dd_words, uint32_t dv_words);

uint8_t bignum_sub_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count);
int32_t bignum_usub(bignum_t *r, bignum_t *a, bignum_t *b, uint32_t min_words, uint32_t total_words);

int32_t bignum_divmod(void *scratch, size_t scratch_size, bignum_t *dd, bignum_t *dv, bignum_t *q, bignum_t *r)
{
	bool free_scratch = false;
	size_t required_scratch_size = 0;

	uint32_t quotient_bits = (dd->bits >= dv->bits) ? dd->bits - dv->bits + 1 : 1;
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

	if (scratch == NULL)
	{
		free_scratch = true;
		scratch = malloc(required_scratch_size);

		if (scratch == NULL)
		{
			return -1;
		}
	}
	else
	{
		if (scratch_size < required_scratch_size)
		{
			return -1;
		}
	}

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

finalize:

	if (free_scratch)
	{
		free(scratch);
	}

	return 0;
}

bignum_t *bignum_div(bignum_t *r, bignum_t *a, bignum_t *b)
{
	int32_t status;

	uint32_t quotient_bits = (a->bits >= b->bits) ? a->bits - b->bits + 1 : 1;
	uint32_t remainder_bits = b->bits;
	int32_t quotient_sign = a->sign * b->sign;

	bignum_t *quotient = r;
	bignum_t *remainder = NULL;

	if (quotient_sign < 0)
	{
		++quotient_bits;
	}

	quotient = bignum_resize(quotient, quotient_bits);

	if (quotient == NULL)
	{
		return NULL;
	}

	remainder = bignum_new(remainder_bits);

	if (remainder == NULL)
	{
		return NULL;
	}

	status = bignum_divmod(NULL, 0, a, b, quotient, remainder);

	bignum_delete(remainder);

	if (status == -1)
	{
		return NULL;
	}

	return r;
}

bignum_t *bignum_mod(bignum_t *r, bignum_t *a, bignum_t *b)
{
	int32_t status;

	uint32_t quotient_bits = (a->bits >= b->bits) ? a->bits - b->bits + 1 : 1;
	uint32_t remainder_bits = b->bits;
	int32_t quotient_sign = a->sign * b->sign;

	bignum_t *quotient = NULL;
	bignum_t *remainder = r;

	if (quotient_sign < 0)
	{
		++quotient_bits;
	}

	remainder = bignum_resize(remainder, remainder_bits);

	if (remainder == NULL)
	{
		return NULL;
	}

	quotient = bignum_new(quotient_bits);

	if (quotient == NULL)
	{
		return NULL;
	}

	status = bignum_divmod(NULL, 0, a, b, quotient, remainder);

	bignum_delete(quotient);

	if (status == -1)
	{
		return NULL;
	}

	return r;
}
