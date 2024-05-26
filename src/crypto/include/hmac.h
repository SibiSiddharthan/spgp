/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include <types.h>

// See NIST FIPS 198-1 The Keyed-Hash Message Authentication Code (HMAC)

#define MAX_HASH_SIZE  64
#define MAX_BLOCK_SIZE 128

typedef enum _hmac_algorithm
{
	HMAC_MD5,
	HMAC_SHA1,
	HMAC_SHA224,
	HMAC_SHA256,
	HMAC_SHA384,
	HMAC_SHA512,
	HMAC_SHA512_224,
	HMAC_SHA512_256,
} hmac_algorithm;

typedef struct _hmac_ctx
{
	hmac_algorithm algorithm;
	size_t ctx_size;
	size_t hash_size;
	size_t block_size;
	size_t key0_size;

	byte_t ihash[MAX_HASH_SIZE];
	byte_t key0[MAX_BLOCK_SIZE];
	byte_t ipad[MAX_BLOCK_SIZE];
	byte_t opad[MAX_BLOCK_SIZE];

	void *_ctx;
	void (*_reset)(void *ctx);
	void (*_update)(void *ctx, void *data, size_t size);
	void (*_final)(void *ctx, byte_t *hash);

} hmac_ctx;

size_t hmac_ctx_size(hmac_algorithm algorithm);

hmac_ctx *hmac_init(void *ptr, size_t size, hmac_algorithm algorithm, byte_t *key, size_t key_size);
hmac_ctx *hmac_new(hmac_algorithm algorithm, byte_t *key, size_t key_size);
void hmac_delete(hmac_ctx *hctx);

void hmac_reset(hmac_ctx *hctx, byte_t *key, size_t key_size);
void hmac_update(hmac_ctx *hctx, void *data, size_t size);
int32_t hmac_final(hmac_ctx *hctx, byte_t *mac, size_t size);

#endif
