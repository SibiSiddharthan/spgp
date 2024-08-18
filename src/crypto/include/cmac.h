/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_cmac_H
#define CRYPTO_cmac_H

#include <types.h>

// See NIST FIPS 198-1 The Keyed-Hash Message Authentication Code (cmac)

typedef enum _cmac_algorithm
{
	// AES
	CMAC_AES128,
	CMAC_AES192,
	CMAC_AES256,
	// ARIA
	CMAC_ARIA128,
	CMAC_ARIA192,
	CMAC_ARIA256,
	// CAMELLIA
	CMAC_CAMELLIA128,
	CMAC_CAMELLIA192,
	CMAC_CAMELLIA256,
	// TDES
	CMAC_TDES,
	// TWOFISH
	CMAC_TWOFISH128,
	CMAC_TWOFISH192,
	CMAC_TWOFISH256,
} cmac_algorithm;

typedef struct _cmac_ctx
{
	cmac_algorithm algorithm;
	uint32_t ctx_size;
	uint32_t key_ctx_size;
	uint32_t block_size;

	size_t message_size;
	byte_t buffer[16];
	byte_t state[16];
	byte_t subkey1[16];
	byte_t subkey2[16];

	void *_key;
	void (*_encrypt_block)(void *key, void *plaintext, void *ciphertext);

} cmac_ctx;

size_t cmac_ctx_size(cmac_algorithm algorithm);

cmac_ctx *cmac_init(void *ptr, size_t size, cmac_algorithm algorithm, void *key, size_t key_size);
cmac_ctx *cmac_new(cmac_algorithm algorithm, void *key, size_t key_size);
void cmac_delete(cmac_ctx *cctx);

void cmac_reset(cmac_ctx *cctx, void *key, size_t key_size);
void cmac_update(cmac_ctx *cctx, void *data, size_t size);
void cmac_generate(cmac_ctx *cctx, void *mac, size_t size);

#endif
