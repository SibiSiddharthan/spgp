/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_MAC_H
#define CRYPTO_MAC_H

#include <types.h>
#include <hash.h>

#define MAX_BLOCK_SIZE 128

typedef struct _hmac_ctx
{
	hash_algorithm algorithm;
	size_t hash_size;
	size_t block_size;
	size_t key0_size;

	byte_t ihash[MAX_HASH_SIZE];
	byte_t key0[MAX_BLOCK_SIZE];
	byte_t ipad[MAX_BLOCK_SIZE];
	byte_t opad[MAX_BLOCK_SIZE];

	void *_ctx;
	void (*_free)(void *ctx);
	void (*_reset)(void *ctx);
	void (*_update)(void *ctx, void *data, size_t size);
	void (*_final)(void *ctx, byte_t *hash);

} hmac_ctx;

hmac_ctx *hmac_new(hash_algorithm algorithm, byte_t *key, size_t key_size);
void hmac_delete(hmac_ctx *hctx);

void hmac_reset(hmac_ctx *hctx, byte_t *key, size_t key_size);
void hmac_update(hmac_ctx *hctx, void *data, size_t size);
int32_t hmac_final(hmac_ctx *hctx, byte_t *mac, size_t size);

#endif
