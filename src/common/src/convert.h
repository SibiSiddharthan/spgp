/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_CONVERT_H
#define COMMON_CONVERT_H

#include <stdint.h>

uint32_t uint_to_hex_common(char buffer[32], uint8_t upper, uint64_t x);
uint64_t uint_from_hex_common(void *buffer, uint8_t size);

static inline uint32_t u8_to_hex(char buffer[32], uint8_t upper, uint8_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

static inline uint32_t u16_to_hex(char buffer[32], uint8_t upper, uint16_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

static inline uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint32_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

static inline uint32_t u64_to_hex(char buffer[32], uint8_t upper, uint64_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

static inline uint8_t u8_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

static inline uint16_t u16_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

static inline uint32_t u32_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

static inline uint64_t u64_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

uint32_t uint_to_oct_common(char buffer[32], uint64_t x);
uint64_t uint_from_oct_common(void *buffer, uint8_t size);

static inline uint32_t u8_to_oct(char buffer[32], uint8_t x)
{
	return uint_to_oct_common(buffer, x);
}

static inline uint32_t u16_to_oct(char buffer[32], uint16_t x)
{
	return uint_to_oct_common(buffer, x);
}

static inline uint32_t u32_to_oct(char buffer[32], uint32_t x)
{
	return uint_to_oct_common(buffer, x);
}

static inline uint32_t u64_to_oct(char buffer[32], uint64_t x)
{
	return uint_to_oct_common(buffer, x);
}

static inline uint8_t u8_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

static inline uint16_t u16_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

static inline uint32_t u32_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

static inline uint64_t u64_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

uint32_t uint_to_bin_common(char buffer[64], uint64_t x);
uint64_t uint_from_bin_common(void *buffer, uint8_t size);

static inline uint32_t u8_to_bin(char buffer[64], uint8_t x)
{
	return uint_to_bin_common(buffer, x);
}

static inline uint32_t u16_to_bin(char buffer[64], uint16_t x)
{
	return uint_to_bin_common(buffer, x);
}

static inline uint32_t u32_to_bin(char buffer[64], uint32_t x)
{
	return uint_to_bin_common(buffer, x);
}

static inline uint32_t u64_to_bin(char buffer[64], uint64_t x)
{
	return uint_to_bin_common(buffer, x);
}

static inline uint8_t u8_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

static inline uint16_t u16_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

static inline uint32_t u32_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

static inline uint64_t u64_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

#endif
