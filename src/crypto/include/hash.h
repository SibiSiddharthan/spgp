/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include <hash-algorithm.h>
#include <types.h>

typedef struct _hash_ctx
{
	hash_algorithm algorithm;
	size_t ctx_size;
	size_t hash_size;
	byte_t hash[MAX_HASH_SIZE];

	void *_ctx;
	void (*_reset)(void *ctx);
	void (*_update)(void *ctx, void *data, size_t);
	void (*_final)(void *ctx, void *hash);
	void (*_final_size)(void *ctx, void *hash, size_t);

} hash_ctx;

size_t hash_ctx_size(hash_algorithm algorithm);

hash_ctx *hash_init(void *ptr, size_t size, hash_algorithm algorithm);
hash_ctx *hash_new(hash_algorithm algorithm);
void hash_delete(hash_ctx *hctx);

void hash_reset(hash_ctx *ctx);
void hash_update(hash_ctx *ctx, void *data, size_t size);
int32_t hash_final(hash_ctx *ctx, void *hash, size_t size);

#endif
