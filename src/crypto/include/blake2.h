/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BLAKE2_H
#define CRYPTO_BLAKE2_H

#include <types.h>

#define BLAKE2B_MAX_HASH_SIZE 64
#define BLAKE2B_MAX_KEY_SIZE 64
#define BLAKE2B_BLOCK_SIZE 128

#define BLAKE2S_MAX_HASH_SIZE 32
#define BLAKE2S_MAX_KEY_SIZE 32
#define BLAKE2S_BLOCK_SIZE 64

typedef struct _blake2b_ctx
{
	uint64_t state[8];
	uint32_t hash_size;
	uint32_t key_size;
	uint64_t size[2];
	byte_t internal[BLAKE2B_BLOCK_SIZE];
} blake2b_ctx;

typedef struct _blake2s_ctx
{
	uint32_t state[8];
	uint32_t hash_size;
	uint32_t key_size;
	uint64_t size;
	byte_t internal[BLAKE2S_BLOCK_SIZE];
} blake2s_ctx;

blake2b_ctx *blake2b_init(uint32_t hash_size, void *key, uint32_t key_size);
void blake2b_free(blake2b_ctx *ctx);
void blake2b_update(blake2b_ctx *ctx, void *data, size_t size);
int32_t blake2b_final(blake2b_ctx *ctx, byte_t *buffer, size_t size);

blake2s_ctx *blake2s_init(uint32_t hash_size, void *key, uint32_t key_size);
void blake2s_free(blake2s_ctx *ctx);
void blake2s_update(blake2s_ctx *ctx, void *data, size_t size);
int32_t blake2s_final(blake2s_ctx *ctx, byte_t *buffer, size_t size);

#endif
