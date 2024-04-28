/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include <types.h>

typedef enum _hash_algorithm
{
	MD5,
	RIPEMD160,
	BLAKE2B,
	BLAKE2S,
	SHA1,
	SHA224,
	SHA256,
	SHA384,
	SHA512,
	SHA512_224,
	SHA512_256,
	SHA3_224,
	SHA3_256,
	SHA3_384,
	SHA3_512
} hash_algorithm;

typedef struct _hash_ctx
{
	hash_algorithm algorithm;
	size_t hash_size;
	size_t max_input_size;
	byte_t hash[64];

	void *ctx;
	void (*_reset)(void *ctx);
	void (*_update)(void *ctx, void *data, size_t size);
	void (*_final)(void *ctx, byte_t *hash, size_t size);
	void (*_free)(void *ctx);

} hash_ctx;

hash_ctx *hash_ctx_new(hash_algorithm algorithm);
void hash_ctx_delete(hash_ctx *hctx);

void hash_ctx_reset(hash_ctx *ctx);
void hash_ctx_update(hash_ctx *ctx, void *data, size_t size);
void hash_ctx_final(hash_ctx *ctx, byte_t *hash, size_t size);

#endif
