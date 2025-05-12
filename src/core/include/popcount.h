/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_POPCOUNT_H
#define SPGP_POPCOUNT_H

#include <stdint.h>

// Count the number of set bits.

static inline uint8_t popcount(uint64_t x, uint8_t bits)
{
	uint8_t count = 0;

	for (uint8_t i = 0; i < bits; ++i)
	{
		if ((x >> i) & 0x1)
		{
			++count;
		}
	}

	return count;
}

#define POPCOUNT_16(x) (popcount(x, 16))
#define POPCOUNT_32(x) (popcount(x, 32))
#define POPCOUNT_64(x) (popcount(x, 64))

#endif
