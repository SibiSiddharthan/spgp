/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <string.h>
#include <bignum.h>
#include <bitscan.h>
#include <round.h>

uint8_t bignum_add_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count);
uint8_t bignum_sub_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count);

void bignum_mul32(uint32_t *r32, uint32_t *a32, uint32_t a32_words, uint32_t w);

// Perform division with a 64 bit dividend with a 32 bit divisor.
static uint32_t div_3_words(uint64_t dd, uint32_t dv_high)
{
	const uint32_t maxq = (1u << 31);

	uint32_t r = 0;
	uint32_t q = 0;

	// Assume dv_high >= (1 << 31) i.e normalized
	q = dd / dv_high;
	r = dd % dv_high;

	// Find a good quotient.
	while (1)
	{
		if (q >= maxq)
		{
			q -= 1;
			r += dv_high;

			if (r < dv_high)
			{
				continue;
			}
		}

		break;
	}

	return q;
}

void bignum_div_words(void *scratch, bn_word_t *dd, bn_word_t *dv, bn_word_t *q, bn_word_t *r, uint32_t dd_words, uint32_t dv_words)
{
	uint32_t *dd32 = (uint32_t *)dd;
	uint32_t *dv32 = (uint32_t *)dv;
	uint32_t *q32 = (uint32_t *)q;
	uint32_t *r32 = (uint32_t *)r;

	size_t dd_size = (dd_words + 1) * sizeof(bn_word_t);

	uint32_t *dd32_norm = (uint32_t *)scratch;
	uint32_t *dv32_norm = (uint32_t *)((byte_t *)scratch + dd_size);
	uint32_t *temp = (uint32_t *)((byte_t *)scratch + (2 * dd_size));

	uint32_t dd32_words = dd_words * 2;
	uint32_t dv32_words = dv_words * 2;
	uint32_t q32_words = 0;
	uint32_t r32_words = 0;

	// Get the correct word count.
	if (dd32[dd32_words - 1] == 0)
	{
		--dd32_words;
	}

	if (dv32[dv32_words - 1] == 0)
	{
		--dv32_words;
	}

	q32_words = dd32_words - dv32_words;
	r32_words = dv32_words;

	// Normalize the divisor, dividend
	uint32_t dv_high = dv32[dv32_words - 1];
	uint32_t shift = 31 - bsr_32(dv_high);

	dv_high <<= shift;

	if (shift != 0)
	{
		uint32_t carry;

		// Left shift dividend
		carry = 0;

		for (uint32_t i = 0; i < dd32_words; ++i)
		{
			dd32_norm[i] = (dd32[i] << shift) | carry;
			carry = dd32[i] >> (BIGNUM_BITS_PER_WORD - shift);
		}

		dd32_norm[dd32_words] = carry;

		// Left shift divisor
		carry = 0;

		for (uint32_t i = 0; i < dv32_words; ++i)
		{
			dv32_norm[i] = (dv32[i] << shift) | carry;
			carry = dv32[i] >> (BIGNUM_BITS_PER_WORD - shift);

			// NOTE : Last carry should be zero.
		}
	}
	else
	{
		memcpy(dd32_norm, dd, dd32_words * sizeof(uint32_t));
		dd32_norm[dd32_words] = 0;
	}

	// The dividend will always be extended by one word.
	++dd32_words;

	for (int32_t i = q32_words - 1; i >= 0; --i)
	{
		uint8_t carry = 0, borrow = 0;
		uint32_t qe = 0;
		uint32_t word_count = CEIL_DIV(i + dv32_words + 1, 2);

		// Estimate a quotient
		qe = div_3_words(((bn_word_t)dd32_norm[i + dv32_words] << 32) + (bn_word_t)dd32_norm[i + dv32_words - 1], dv_high);

		if (qe == 0)
		{
			// Zero shortcut
			q32[i] = qe;
			continue;
		}

		// Calculate q*dv
		memset(temp, 0, (dd32_words + 1) * sizeof(uint32_t)); // For safety.
		bignum_mul32(temp + i, dv32_norm, dv32_words, qe);    // Left shifted

		borrow = bignum_sub_words((bn_word_t *)dd32_norm, (bn_word_t *)dd32_norm, (bn_word_t *)temp, word_count);

		if (borrow > 0)
		{
			while (carry != 1)
			{
				carry = bignum_add_words((bn_word_t *)dd32_norm, (bn_word_t *)dd32_norm, (bn_word_t *)dv32, word_count);
				--qe;
			}
		}

		// Set the quotient.
		q32[i] = qe;
	}

	// Unnormalize the remainder.
	for (uint32_t i = 0; i < r32_words; ++i)
	{
		r32[i] = (dd32_norm[i] >> shift) | (dd32_norm[i + 1] << (32 - shift));
	}
}
