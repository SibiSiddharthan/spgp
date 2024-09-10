/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_XOR_H
#define CRYPTO_XOR_H

#include <stdint.h>
#include <ptr.h>

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
