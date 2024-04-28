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
	void *ctx;
	void (*reset)(void *ctx);
	void (*update)(void *ctx, void *data, size_t size);
	void (*final)(void *ctx, byte_t *hash, size_t size);
	void (*free)(void *ctx);
} hash_ctx;

#endif
