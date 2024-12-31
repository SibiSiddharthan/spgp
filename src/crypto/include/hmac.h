/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include <hash-algorithm.h>
#include <types.h>

// See NIST FIPS 198-1 The Keyed-Hash Message Authentication Code (HMAC)

typedef struct _hmac_ctx
{
	hash_algorithm algorithm;
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
	void (*_final)(void *ctx, void *hash);

} hmac_ctx;

size_t hmac_ctx_size(hash_algorithm algorithm);

hmac_ctx *hmac_init(void *ptr, size_t size, hash_algorithm algorithm, void *key, size_t key_size);
hmac_ctx *hmac_new(hash_algorithm algorithm, void *key, size_t key_size);
void hmac_delete(hmac_ctx *hctx);

void hmac_reset(hmac_ctx *hctx, void *key, size_t key_size);
void hmac_update(hmac_ctx *hctx, void *data, size_t size);
uint32_t hmac_final(hmac_ctx *hctx, void *mac, size_t size);

uint32_t hmac_md5(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_ripemd160(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha1(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha224(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha256(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha384(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha512(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha512_224(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha512_256(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha3_224(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha3_256(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha3_384(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t hmac_sha3_512(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);

#endif
