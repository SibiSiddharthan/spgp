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

uint8_t bignum_sub_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count);
void bignum_div_words(bn_word_t *dd, bn_word_t *dv, bn_word_t *q, bn_word_t *r, uint32_t dd_words, uint32_t dv_words);

int32_t bignum_divmod(bignum_t *dd, bignum_t *dv, bignum_t **q, bignum_t **r)
{
	bool quotient_needed = true;
	bool remainder_needed = true;

	uint32_t quotient_bits = dd->bits - dv->bits;
	uint32_t remainder_bits = dv->bits;

	bignum_t *quotient = NULL;
	bignum_t *remainder = NULL;

	// Zero divisor, error.
	if (dv->bits == 0)
	{
		return -1;
	}

	if (q == NULL)
	{
		quotient_needed = false;
		q = &quotient;
	}

	if (r == NULL)
	{
		remainder_needed = false;
		r = &remainder;
	}

	// What is the point of going further?
	if (!quotient_needed && !remainder_needed)
	{
		return -1;
	}

	// Initialize the quotient
	if (*q == NULL)
	{
		*q = bignum_new(quotient_bits);

		if (*q == NULL)
		{
			return -1;
		}
	}
	else
	{
		if ((*q)->bits < quotient_bits)
		{
			return -1;
		}
	}

	// Initialize the remainder
	if (*r == NULL)
	{
		*r = bignum_new(remainder_bits);

		if (*r == NULL)
		{
			return -1;
		}
	}
	else
	{
		if ((*r)->bits < remainder_bits)
		{
			return -1;
		}
	}

	if (*q == NULL || *r == NULL)
	{
		bignum_free(*q);
		bignum_free(*r);

		return -1;
	}

	// Zero dividend
	if (dd->bits == 0)
	{
		bignum_zero(*q);
		bignum_zero(*r);

		goto finalize;
	}

	// Divisor is greater than dividend
	if (dv->bits >= dd->bits)
	{
		if (dv->bits == dd->bits)
		{
			// Divisor may be greater than dividend. Subract divisor from dividend,
			// if remainder is negative jump to else. Otherwise quotient must be 1.
			uint8_t borrow = bignum_sub_words((*r)->words, dd->words, dv->words, CEIL_DIV(dd->bits, BIGNUM_BITS_PER_WORD));

			if (borrow)
			{
				goto zero_quotient;
			}

			// Set quotient to 1.
			(*q)->words[0] = 1;
			(*q)->bits = 1;
			(*q)->sign = dd->sign * dv->sign;

			(*r)->bits = bignum_bitcount(*r);
			(*r)->sign = dv->sign;

			goto finalize;
		}
		else
		{

		zero_quotient:
			bignum_zero(*q);
			bignum_copy(*r, sizeof(bignum_t) + (*r)->size, dv);

			goto finalize;
		}
	}

	// General case long division.
	bignum_div_words(dd->words, dv->words, (*q)->words, (*r)->words, CEIL_DIV(dd->bits, BIGNUM_BITS_PER_WORD),
					 CEIL_DIV(dv->bits, BIGNUM_BITS_PER_WORD));

	(*q)->bits = bignum_bitcount(*q);
	(*r)->bits = bignum_bitcount(*r);

	// The sign of the remainder will be same as that of the divisor.
	(*q)->sign = dd->sign * dv->sign;
	(*r)->sign = dv->sign;

finalize:
	if (!quotient_needed)
	{
		bignum_free(quotient);
	}

	if (!remainder_needed)
	{
		bignum_free(remainder);
	}

	return 0;
}

bignum_t *bignum_div(bignum_t *r, bignum_t *a, bignum_t *b)
{
	int32_t status = bignum_divmod(a, b, &r, NULL);

	if (status == -1)
	{
		return NULL;
	}

	return r;
}

bignum_t *bignum_mod(bignum_t *r, bignum_t *a, bignum_t *b)
{
	int32_t status = bignum_divmod(a, b, NULL, &r);

	if (status == -1)
	{
		return NULL;
	}

	return r;
}
