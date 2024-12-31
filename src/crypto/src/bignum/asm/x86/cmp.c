/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <intrin.h>

// If a > b ->  1
// If a < b -> -1
// If a = b ->  0
int32_t bignum_cmp_words(uint64_t *a, uint64_t *b, uint32_t count)
{
	uint64_t result = 0;
	uint8_t borrow = 0;

	// Start from MSB
	a += (count - 1);
	b += (count - 1);

	for (int32_t pos = 0; pos < count; ++pos, --a, --b)
	{
		borrow = _subborrow_u64(borrow, *a, *b, &result);

		if (result == 0)
		{
			continue;
		}

		// a < b
		if (borrow != 0)
		{
			return -1;
		}
		// a > b
		else
		{
			return 1;
		}
	}

	// a = b
	return 0;
}
