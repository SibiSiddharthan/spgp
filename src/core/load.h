/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_LOAD_H
#define SPGP_LOAD_H

#include <types.h>

#define LOAD_8(d, s)                       \
	{                                      \
		*(uint8_t *)(d) = *(uint8_t *)(s); \
	}
#define LOAD_16(d, s)                        \
	{                                        \
		*(uint16_t *)(d) = *(uint16_t *)(s); \
	}
#define LOAD_32(d, s)                        \
	{                                        \
		*(uint32_t *)(d) = *(uint32_t *)(s); \
	}
#define LOAD_64(d, s)                        \
	{                                        \
		*(uint64_t *)(d) = *(uint64_t *)(s); \
	}

#endif
