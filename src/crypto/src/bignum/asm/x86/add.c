/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <intrin.h>

uint8_t bignum_add_words(uint64_t *r, uint64_t *a, uint64_t *b, uint32_t count)
{
	uint8_t carry = 0;

	for (uint32_t pos = 0; pos < count; ++pos)
	{
		carry = _addcarry_u64(carry, *a, *b, *r);

		a++;
		b++;
		r++;
	}

	return carry;
}

void bignum_increment(uint64_t *r, uint32_t count)
{
	uint8_t carry = 0;

	for (uint32_t pos = 0; pos < count; ++pos)
	{
		carry = _addcarry_u64(carry, *r, 1, *r);

		// If there is no carry, return.
		if (carry == 0)
		{
			return;
		}

		r++;
	}
}
