/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_cmac_H
#define CRYPTO_cmac_H

#include <cipher-algorithm.h>
#include <types.h>

// See NIST FIPS 800-38B Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication (CMAC)

typedef struct _cmac_ctx
{
	cipher_algorithm algorithm;
	uint32_t ctx_size;
	uint32_t block_size;

	size_t message_size;
	byte_t buffer[16];
	byte_t state[16];
	byte_t subkey1[16];
	byte_t subkey2[16];

	void *_key;
	void (*_encrypt)(void *key, void *plaintext, void *ciphertext);
	void (*_process)(struct _cmac_ctx *ctx);

} cmac_ctx;

size_t cmac_ctx_size(cipher_algorithm algorithm);

cmac_ctx *cmac_init(void *ptr, size_t size, cipher_algorithm algorithm, void *key, size_t key_size);
cmac_ctx *cmac_new(cipher_algorithm algorithm, void *key, size_t key_size);
void cmac_delete(cmac_ctx *cctx);

cmac_ctx *cmac_reset(cmac_ctx *cctx, void *key, size_t key_size);
void cmac_update(cmac_ctx *cctx, void *data, size_t size);
uint32_t cmac_final(cmac_ctx *cctx, void *mac, size_t size);

uint32_t aes128_cmac(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t aes192_cmac(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);
uint32_t aes256_cmac(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size);

#endif
