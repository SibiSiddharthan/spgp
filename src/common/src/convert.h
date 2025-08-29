/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_CONVERT_H
#define COMMON_CONVERT_H

#include <stdint.h>

#ifdef _WIN32
typedef long long ssize_t;
#endif

uint32_t uint_to_hex_common(char buffer[32], uint8_t upper, uintmax_t x);
uintmax_t uint_from_hex_common(void *buffer, uint8_t size);

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

static inline uint32_t umax_to_hex(char buffer[32], uint8_t upper, uintmax_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

static inline uint32_t usize_to_hex(char buffer[32], uint8_t upper, size_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

static inline uint32_t uptr_to_hex(char buffer[32], uint8_t upper, uintptr_t x)
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

static inline uintmax_t umax_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

static inline size_t usize_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

static inline uintptr_t uptr_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

uint32_t uint_to_oct_common(char buffer[32], uintmax_t x);
uintmax_t uint_from_oct_common(void *buffer, uint8_t size);

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

static inline uint32_t umax_to_oct(char buffer[32], uintmax_t x)
{
	return uint_to_oct_common(buffer, x);
}

static inline uint32_t usize_to_oct(char buffer[32], size_t x)
{
	return uint_to_oct_common(buffer, x);
}

static inline uint32_t uptr_to_oct(char buffer[32], uintptr_t x)
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

static inline uintmax_t umax_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

static inline size_t usize_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

static inline uintptr_t uptr_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

uint32_t uint_to_bin_common(char buffer[64], uintmax_t x);
uintmax_t uint_from_bin_common(void *buffer, uint8_t size);

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

static inline uint32_t umax_to_bin(char buffer[32], uintmax_t x)
{
	return uint_to_bin_common(buffer, x);
}

static inline uint32_t usize_to_bin(char buffer[32], size_t x)
{
	return uint_to_bin_common(buffer, x);
}

static inline uint32_t uptr_to_bin(char buffer[32], uintptr_t x)
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

static inline uintmax_t umax_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

static inline size_t usize_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

static inline uintptr_t uptr_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

uint32_t uint_to_dec_common(char buffer[32], uintmax_t x);
uintmax_t uint_from_dec_common(void *buffer, uint8_t size);

static inline uint32_t u8_to_dec(char buffer[32], uint8_t x)
{
	return uint_to_dec_common(buffer, x);
}

static inline uint32_t u16_to_dec(char buffer[32], uint16_t x)
{
	return uint_to_dec_common(buffer, x);
}

static inline uint32_t u32_to_dec(char buffer[32], uint32_t x)
{
	return uint_to_dec_common(buffer, x);
}

static inline uint32_t u64_to_dec(char buffer[32], uint64_t x)
{
	return uint_to_dec_common(buffer, x);
}

static inline uint32_t umax_to_dec(char buffer[32], uintmax_t x)
{
	return uint_to_dec_common(buffer, x);
}

static inline uint32_t usize_to_dec(char buffer[32], size_t x)
{
	return uint_to_dec_common(buffer, x);
}

static inline uint32_t uptr_to_dec(char buffer[32], uintptr_t x)
{
	return uint_to_dec_common(buffer, x);
}

static inline uint8_t u8_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

static inline uint16_t u16_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

static inline uint32_t u32_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

static inline uint64_t u64_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

static inline uintmax_t umax_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

static inline size_t usize_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

static inline uintptr_t uptr_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

uint32_t int_to_dec_common(char buffer[32], intmax_t x);
intmax_t int_from_dec_common(void *buffer, uint8_t size);

static inline uint32_t i8_to_dec(char buffer[32], int8_t x)
{
	return int_to_dec_common(buffer, x);
}

static inline uint32_t i16_to_dec(char buffer[32], int16_t x)
{
	return int_to_dec_common(buffer, x);
}

static inline uint32_t i32_to_dec(char buffer[32], int32_t x)
{
	return int_to_dec_common(buffer, x);
}

static inline uint32_t i64_to_dec(char buffer[32], int64_t x)
{
	return int_to_dec_common(buffer, x);
}

static inline uint32_t imax_to_dec(char buffer[32], intmax_t x)
{
	return int_to_dec_common(buffer, x);
}

static inline uint32_t isize_to_dec(char buffer[32], ssize_t x)
{
	return int_to_dec_common(buffer, x);
}

static inline uint32_t iptr_to_dec(char buffer[32], intptr_t x)
{
	return int_to_dec_common(buffer, x);
}

static inline int8_t i8_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

static inline int16_t i16_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

static inline int32_t i32_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

static inline int64_t i64_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

static inline intmax_t imax_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

static inline ssize_t isize_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

static inline intptr_t iptr_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

float float32_from_hex(void *buffer, uint8_t size);
uint32_t float32_to_hex(char buffer[64], uint8_t upper, float x);

double float64_from_hex(void *buffer, uint8_t size);
uint32_t float64_to_hex(char buffer[64], uint8_t upper, double x);

double float_from_normal_common(void *buffer, uint8_t size);

static inline float float32_from_normal(void *buffer, uint8_t size)
{
	return (float)float_from_normal_common(buffer, size);
}

static inline double float64_from_normal(void *buffer, uint8_t size)
{
	return (double)float_from_normal_common(buffer, size);
}

double float_from_scientific_common(void *buffer, uint8_t size);

static inline float float32_from_scientific(void *buffer, uint8_t size)
{
	return (float)float_from_scientific_common(buffer, size);
}

static inline double float64_from_scientific(void *buffer, uint8_t size)
{
	return (double)float_from_scientific_common(buffer, size);
}

#endif
