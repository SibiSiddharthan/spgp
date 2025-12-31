/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_XOR_H
#define COMMON_XOR_H

#include <stdint.h>
#include <ptr.h>

static inline void xor8(void *r, void *a, void *b, size_t n)
{
	uint64_t *r64 = r;
	uint64_t *a64 = a;
	uint64_t *b64 = b;

	while (n != 0)
	{
		*r64 = *a64 ^ *b64;

		r64++;
		a64++;
		b64++;
		n -= 8;
	}
}

#define XOR8_N(R, A, B, N) xor8(R, A, B, N)

#define XOR8(R, A, B)                                                 \
	{                                                                 \
		*((uint64_t *)(R)) = *((uint64_t *)(A)) ^ *((uint64_t *)(B)); \
	}

#define XOR16(R, A, B)                                              \
	{                                                               \
		XOR8(R, A, B);                                              \
		XOR8(PTR_OFFSET(R, 8), PTR_OFFSET(A, 8), PTR_OFFSET(B, 8)); \
	}

#define XOR32(R, A, B)                                                 \
	{                                                                  \
		XOR8(R, A, B);                                                 \
		XOR8(PTR_OFFSET(R, 8), PTR_OFFSET(A, 8), PTR_OFFSET(B, 8));    \
		XOR8(PTR_OFFSET(R, 16), PTR_OFFSET(A, 16), PTR_OFFSET(B, 16)); \
		XOR8(PTR_OFFSET(R, 32), PTR_OFFSET(A, 32), PTR_OFFSET(B, 32)); \
	}

#endif
