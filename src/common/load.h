/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_LOAD_H
#define COMMON_LOAD_H

#include <stdint.h>
#include <byteswap.h>

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

#define LOAD_16BE(d, s)                                \
	{                                                  \
		*(uint16_t *)(d) = *(uint16_t *)(s);           \
		*(uint16_t *)(d) = BSWAP_16(*(uint16_t *)(d)); \
	}

#define LOAD_32BE(d, s)                                \
	{                                                  \
		*(uint32_t *)(d) = *(uint32_t *)(s);           \
		*(uint32_t *)(d) = BSWAP_32(*(uint32_t *)(d)); \
	}

#define LOAD_64BE(d, s)                                \
	{                                                  \
		*(uint64_t *)(d) = *(uint64_t *)(s);           \
		*(uint64_t *)(d) = BSWAP_64(*(uint64_t *)(d)); \
	}

#endif
