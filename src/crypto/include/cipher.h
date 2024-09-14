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
	PADDING_NONE,
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
	byte_t buffer[32];

	void *_ctx;
	void (*_encrypt)(void *, void *, void *);
	void (*_decrypt)(void *, void *, void *);
} cipher_ctx;

size_t cipher_ctx_size(cipher_algorithm algorithm);

cipher_ctx *cipher_init(void *ptr, size_t size, cipher_algorithm algorithm, void *key, size_t key_size);
cipher_ctx *cipher_new(cipher_algorithm algorithm, void *key, size_t key_size);
void cipher_delete(cipher_ctx *cctx);

cipher_ctx *cipher_reset(cipher_ctx *cctx, void *key, size_t key_size);

// Electronic Code Book (ECB)

cipher_ctx *cipher_ecb_encrypt_init(cipher_ctx *cctx, cipher_padding padding);
uint64_t cipher_ecb_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_ecb_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_ecb_encrypt(cipher_ctx *cctx, cipher_padding padding, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size);

cipher_ctx *cipher_ecb_decrypt_init(cipher_ctx *cctx, cipher_padding padding);
uint64_t cipher_ecb_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_ecb_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_ecb_decrypt(cipher_ctx *cctx, cipher_padding padding, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size);

// Cipher Block Chaining (CBC)

cipher_ctx *cipher_cbc_encrypt_init(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size);
uint64_t cipher_cbc_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cbc_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cbc_encrypt(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size,
							void *ciphertext, size_t ciphertext_size);

cipher_ctx *cipher_cbc_decrypt_init(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size);
uint64_t cipher_cbc_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cbc_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cbc_decrypt(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size,
							void *plaintext, size_t plaintext_size);

// Cipher Feedback (CFB{1,8,64,128})

cipher_ctx *cipher_cfb1_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_cfb1_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cfb1_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cfb1_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							 size_t ciphertext_size);

cipher_ctx *cipher_cfb1_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_cfb1_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cfb1_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cfb1_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							 size_t plaintext_size);

cipher_ctx *cipher_cfb8_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_cfb8_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cfb8_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cfb8_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							 size_t ciphertext_size);

cipher_ctx *cipher_cfb8_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_cfb8_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cfb8_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cfb8_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							 size_t plaintext_size);

cipher_ctx *cipher_cfb64_encrypt_init(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size);
uint64_t cipher_cfb64_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cfb64_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cfb64_encrypt(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size,
							  void *ciphertext, size_t ciphertext_size);

cipher_ctx *cipher_cfb64_decrypt_init(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size);
uint64_t cipher_cfb64_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cfb64_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cfb64_decrypt(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size,
							  void *plaintext, size_t plaintext_size);

cipher_ctx *cipher_cfb128_encrypt_init(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size);
uint64_t cipher_cfb128_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cfb128_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_cfb128_encrypt(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size,
							   void *ciphertext, size_t ciphertext_size);

cipher_ctx *cipher_cfb128_decrypt_init(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size);
uint64_t cipher_cfb128_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cfb128_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_cfb128_decrypt(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size,
							   void *plaintext, size_t plaintext_size);

// Output Feedback (OFB)

cipher_ctx *cipher_ofb_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_ofb_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_ofb_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_ofb_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size);

cipher_ctx *cipher_ofb_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_ofb_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_ofb_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_ofb_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size);

// Counter (CTR)

void cipher_ctr_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_ctr_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_ctr_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
void cipher_ctr_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
						size_t ciphertext_size);

void cipher_ctr_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_ctr_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_ctr_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
void cipher_ctr_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
						size_t plaintext_size);

#endif
