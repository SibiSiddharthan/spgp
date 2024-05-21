/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CIPHER_H
#define CRYPTO_CIPHER_H

#include <types.h>

typedef enum _cipher_mode
{
	MODE_NONE,
	MODE_ECB,
	MODE_CBC,
	MODE_CTR
} cipher_mode;

typedef enum _cipher_type
{
	CIPHER_STREAM,
	CIPHER_BLOCK
} cipher_type;

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

typedef struct _cipher_ctx
{
	cipher_algorithm algorithm;
	cipher_mode mode;
	cipher_type type;
	uint32_t block_size;
	size_t ctx_size;

	void *_ctx;
	void (*_encrypt_block)(void *, void *, void *);
	void (*_decrypt_block)(void *, void *, void *);
	void (*_encrypt_stream)(void *, void *, void *);
	void (*_decrypt_stream)(void *, void *, void *);
} cipher_ctx;

size_t cipher_ctx_size(cipher_algorithm algorithm);

cipher_ctx *cipher_init(void *ptr, size_t size, cipher_algorithm algorithm, cipher_mode mode, byte_t *key, size_t key_size);
cipher_ctx *cipher_new(cipher_algorithm algorithm, cipher_mode mode, byte_t *key, size_t key_size);
void cipher_delete(cipher_ctx *cctx);
void cipher_reset(cipher_ctx *cctx, cipher_mode mode);

void cipher_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
void cipher_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);

void cipher_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
void cipher_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

#endif
