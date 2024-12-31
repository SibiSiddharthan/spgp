/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <bignum.h>

void bignum_increment(bn_word_t *r, uint32_t count);

uint8_t bignum_sub_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count)
{
	uint8_t borrow = 0;
	bn_word_t temp_a = 0;
	bn_word_t temp_b = 0;
	bn_word_t temp_r = 0;

	for (uint32_t pos = 0; pos < count; ++pos)
	{
		temp_a = *a;
		temp_b = *b;

		// Subract previous borrow
		*r = temp_a - borrow; // borrow -> 0|1
		borrow = (*r > temp_a); // Next borrow
		temp_r = *r;
		*r -= temp_b;
		borrow |= (*r > temp_r); // Next borrow

		a++;
		b++;
		r++;
	}

	return borrow;
}

void bignum_decrement(bn_word_t *r, uint32_t count)
{
	for (uint32_t pos = 0; pos < count; ++pos)
	{
		--(*r);

		// If there is no carry, return.
		if (*r != (bn_word_t)-1)
		{
			return;
		}

		r++;
	}
}

void bignum_2complement(bn_word_t *r, uint32_t count)
{
	bn_word_t *t = r;

	// Invert
	for (uint32_t pos = 0; pos < count; ++pos)
	{
		*t = ~(*t);
		t++;
	}

	// Add one
	bignum_increment(r, count);
}
