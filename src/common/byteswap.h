/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_BYTESWAP_H
#define COMMON_BYTESWAP_H

#include <stdint.h>

// Given an unsigned N-bit argument X, reverse the byte order and return.

// clang-format off
#define BSWAP_16(x) ((((uint16_t)(x) & (uint16_t)0x00FF) << 8) | \
                     (((uint16_t)(x) & (uint16_t)0xFF00) >> 8))

#define BSWAP_32(x) ((((uint32_t)(x) & (uint32_t)0x000000FF) << 24) | \
                     (((uint32_t)(x) & (uint32_t)0x0000FF00) << 8)  | \
                     (((uint32_t)(x) & (uint32_t)0x00FF0000) >> 8)  | \
                     (((uint32_t)(x) & (uint32_t)0xFF000000) >> 24))

#define BSWAP_64(x) ((((uint64_t)(x) & (uint64_t)0x00000000000000FF) << 56) | \
                     (((uint64_t)(x) & (uint64_t)0x000000000000FF00) << 40) | \
                     (((uint64_t)(x) & (uint64_t)0x0000000000FF0000) << 24) | \
                     (((uint64_t)(x) & (uint64_t)0x00000000FF000000) << 8)  | \
                     (((uint64_t)(x) & (uint64_t)0x000000FF00000000) >> 8)  | \
                     (((uint64_t)(x) & (uint64_t)0x0000FF0000000000) >> 24) | \
                     (((uint64_t)(x) & (uint64_t)0x00FF000000000000) >> 40) | \
                     (((uint64_t)(x) & (uint64_t)0xFF00000000000000) >> 56))

// clang-format on
#endif
