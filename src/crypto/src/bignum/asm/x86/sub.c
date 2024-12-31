/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <intrin.h>

uint8_t bignum_sub_words(uint64_t *r, uint64_t *a, uint64_t *b, uint32_t count)
{
	uint8_t borrow = 0;

	for (uint32_t pos = 0; pos < count; ++pos)
	{
		borrow = _subborrow_u64(borrow, *a, *b, *r);

		a++;
		b++;
		r++;
	}

	return borrow;
}

void bignum_decrement(uint64_t *r, uint32_t count)
{
	uint8_t borrow = 0;

	for (uint32_t pos = 0; pos < count; ++pos)
	{
		borrow = _subborrow_u64(borrow, *r, 1, *r);

		// If there is no borrow, return.
		if (borrow == 0)
		{
			return;
		}

		r++;
	}
}

void bignum_2complement(uint64_t *r, uint32_t count)
{
	uint64_t *t = r;

	// Invert
	for (uint32_t pos = 0; pos < count; ++pos)
	{
		*t = ~(*t);
		t++;
	}

	// Add one
	bignum_increment(r, count);
}

