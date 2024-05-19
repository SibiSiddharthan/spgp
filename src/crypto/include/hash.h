/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include <types.h>

#define MAX_HASH_SIZE 64

typedef enum _hash_algorithm
{
	HASH_MD5,
	HASH_RIPEMD160,
	HASH_BLAKE2B,
	HASH_BLAKE2S,
	HASH_SHA1,
	HASH_SHA224,
	HASH_SHA256,
	HASH_SHA384,
	HASH_SHA512,
	HASH_SHA512_224,
	HASH_SHA512_256,
	HASH_SHA3_224,
	HASH_SHA3_256,
	HASH_SHA3_384,
	HASH_SHA3_512
} hash_algorithm;

typedef struct _hash_ctx
{
	hash_algorithm algorithm;
	size_t ctx_size;
	size_t hash_size;
	size_t max_input_size;
	byte_t hash[MAX_HASH_SIZE];

	void *_ctx;
	void (*_reset)(void *ctx);
	void (*_update)(void *ctx, void *data, size_t size);
	void (*_final)(void *ctx, byte_t *hash);
	void (*_final_size)(void *ctx, byte_t *hash, size_t);

} hash_ctx;

size_t hash_ctx_size(hash_algorithm algorithm);

hash_ctx *hash_init(void *ptr, size_t size, hash_algorithm algorithm);
hash_ctx *hash_new(hash_algorithm algorithm);
void hash_delete(hash_ctx *hctx);

void hash_reset(hash_ctx *ctx);
void hash_update(hash_ctx *ctx, void *data, size_t size);
int32_t hash_final(hash_ctx *ctx, byte_t *hash, size_t size);

#endif
