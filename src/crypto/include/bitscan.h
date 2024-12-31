/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BITSCAN_H
#define CRYPTO_BITSCAN_H

#include <types.h>

static inline uint32_t bsf_8(uint8_t x)
{
	for (uint8_t i = 0; i < 8; ++i)
	{
		if (x & (1 << i))
		{
			return i;
		}
	}

	return 0;
}

static inline uint32_t bsr_8(uint8_t x)
{
	for (uint8_t i = 7; i > 0; --i)
	{
		if (x & (1 << i))
		{
			return i;
		}
	}

	return 0;
}

static inline uint32_t bsf_32(uint32_t x)
{
	uint8_t y = 0;

	y = x & 0xFF;

	if (y != 0)
	{
		return bsf_8(y);
	}

	y = (x >> 8) & 0xFF;

	if (y != 0)
	{
		return 8 + bsf_8(y);
	}

	y = (x >> 16) & 0xFF;

	if (y != 0)
	{
		return 16 + bsf_8(y);
	}

	y = (x >> 24) & 0xFF;

	if (y != 0)
	{
		return 24 + bsf_8(y);
	}

	return 0;
}

static inline uint32_t bsr_32(uint32_t x)
{
	uint8_t y = 0;

	y = (x >> 24) & 0xFF;

	if (y != 0)
	{
		return 24 + bsr_8(y);
	}

	y = (x >> 16) & 0xFF;

	if (y != 0)
	{
		return 16 + bsr_8(y);
	}

	y = (x >> 8) & 0xFF;

	if (y != 0)
	{
		return 8 + bsr_8(y);
	}

	y = x & 0xFF;

	if (y != 0)
	{
		return bsr_8(y);
	}

	return 0;
}

static inline uint32_t bsf_64(uint64_t x)
{
	return (x & 0xFFFFFFFF) != 0 ? bsf_32(x & 0xFFFFFFFF) : (32 + bsf_32((x >> 32) & 0xFFFFFFFF));
}

static inline uint32_t bsr_64(uint64_t x)
{
	return ((x >> 32) & 0xFFFFFFFF) != 0 ? (32 + bsr_32((x >> 32) & 0xFFFFFFFF)) : bsr_32(x & 0xFFFFFFFF);
}

// Returns the index of set bit (LSB -> MSB)
#define BSF_32(X) bsf_32(X)
#define BSF_64(X) bsf_64(X)

// Returns the index of set bit (MSB -> LSB)
#define BSR_32(X) bsr_32(X)
#define BSR_64(X) bsr_64(X)

#endif
