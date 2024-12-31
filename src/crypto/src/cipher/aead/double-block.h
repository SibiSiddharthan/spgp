/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DOUBLE_BLOCK_H
#define CRYPTO_DOUBLE_BLOCK_H

#include <types.h>
#include <byteswap.h>

static inline void double_block(byte_t r[16], byte_t b[16])
{
	uint64_t *u = (uint64_t *)b;
	uint64_t *v = (uint64_t *)r;

	v[0] = BSWAP_64(u[0]);
	v[1] = BSWAP_64(u[1]);

	v[0] = (v[0] << 1) | ((u[1] & 0x80) ? 1 : 0);
	v[1] = v[1] << 1;

	v[0] = BSWAP_64(v[0]);
	v[1] = BSWAP_64(v[1]);

	if (b[0] & 0x80)
	{
		r[15] ^= 0x87;
	}
}

#endif
