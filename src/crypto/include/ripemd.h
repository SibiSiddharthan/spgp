/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_RIPEMD_H
#define CRYPTO_RIPEMD_H

#include <types.h>

// See RIPEMD-160: A Strengthened Version of RIPEMD

#define RIPEMD160_HASH_SIZE  20
#define RIPEMD160_BLOCK_SIZE 64

typedef struct _ripemd160_ctx
{
	uint32_t h0, h1, h2, h3, h4;
	uint64_t size;
	byte_t internal[RIPEMD160_BLOCK_SIZE];
} ripemd160_ctx;

ripemd160_ctx *ripemd160_init(void *ptr, size_t size);
ripemd160_ctx *ripemd160_new(void);
void ripemd160_delete(ripemd160_ctx *ctx);
void ripemd160_reset(ripemd160_ctx *ctx);
void ripemd160_update(ripemd160_ctx *ctx, void *data, size_t size);
void ripemd160_final(ripemd160_ctx *ctx, byte_t buffer[RIPEMD160_HASH_SIZE]);
void ripemd160_hash(void *data, size_t size, byte_t buffer[RIPEMD160_HASH_SIZE]);

#endif
