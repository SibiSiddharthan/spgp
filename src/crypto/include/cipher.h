/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CIPHER_H
#define CRYPTO_CIPHER_H

#include <types.h>

typedef enum _cipher_algorithm
{
	// AES
	CIPHER_AES128,
	CIPHER_AES192,
	CIPHER_AES256,
	// ARIA
	CIPHER_ARIA128,
	CIPHER_ARIA192,
	CIPHER_ARIA256,
	// CAMELLIA
	CIPHER_CAMELLIA128,
	CIPHER_CAMELLIA192,
	CIPHER_CAMELLIA256,
	// CHACHA
	CIPHER_CHACHA20,
	// TDES
	CIPHER_TDES,
	// TWOFISH
	CIPHER_TWOFISH128,
	CIPHER_TWOFISH192,
	CIPHER_TWOFISH256,
} cipher_algorithm;

typedef enum _cipher_padding
{
	PADDING_ZERO,
	PADDING_ISO7816,
	PADDING_PKCS7
} cipher_padding;

typedef struct _cipher_ctx
{
	cipher_algorithm algorithm;
	cipher_padding padding;
	uint16_t ctx_size;
	uint16_t block_size;
	size_t message_size;
	byte_t buffer[64];

	void *_ctx;
	void *(*_init)(void *, size_t, void *, size_t);
	void (*_encrypt)(void *, void *, void *);
	void (*_decrypt)(void *, void *, void *);
} cipher_ctx;

size_t cipher_ctx_size(cipher_algorithm algorithm);

cipher_ctx *cipher_init(void *ptr, size_t size, cipher_algorithm algorithm, void *key, size_t key_size);
cipher_ctx *cipher_new(cipher_algorithm algorithm, void *key, size_t key_size);
void cipher_delete(cipher_ctx *cctx);

#endif
