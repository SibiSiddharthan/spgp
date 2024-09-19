/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CIPHER_H
#define CRYPTO_CIPHER_H

#include <cipher-algorithm.h>
#include <types.h>

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

	union {
		struct _gcm
		{
			byte_t h[16];
			byte_t j[16];
			byte_t s[16];
			byte_t icb[16];

			size_t data_size;
			size_t ad_size;
		} gcm;

		struct _eax
		{
			byte_t b[16];
			byte_t p[16];
			byte_t n[16];
			byte_t h[16];
			byte_t c[16];

			byte_t tag_size;
			size_t data_size;
			size_t ad_size;
		} eax;
	};

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

cipher_ctx *cipher_ctr_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_ctr_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_ctr_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_ctr_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size);

cipher_ctx *cipher_ctr_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size);
uint64_t cipher_ctr_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_ctr_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_ctr_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size);

// Galois Counter Mode (GCM)
cipher_ctx *cipher_gcm_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size);
uint64_t cipher_gcm_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_gcm_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size,
								  void *tag, size_t tag_size);
uint64_t cipher_gcm_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size, void *plaintext,
							size_t plaintext_size, void *ciphertext, size_t ciphertext_size, void *tag, size_t tag_size);

cipher_ctx *cipher_gcm_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size);
uint64_t cipher_gcm_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_gcm_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size,
								  void *tag, size_t tag_size);
uint64_t cipher_gcm_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size, void *ciphertext,
							size_t ciphertext_size, void *plaintext, size_t plaintext_size, void *tag, size_t tag_size);

// Cipher Block Chaining-Message Authentication Code (CCM)
uint64_t cipher_ccm_encrypt(cipher_ctx *cctx, byte_t tag_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size,
							void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_ccm_decrypt(cipher_ctx *cctx, byte_t tag_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size,
							void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

// Key Wrapping
uint32_t cipher_key_wrap_encrypt(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint32_t cipher_key_wrap_decrypt(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

uint32_t cipher_key_wrap_pad_encrypt(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint32_t cipher_key_wrap_pad_decrypt(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

// Encrypt Authenticate Translate (EAX)
cipher_ctx *cipher_eax_encrypt_init(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *header, size_t header_size);
uint64_t cipher_eax_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_eax_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint64_t cipher_eax_encrypt(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *header, size_t header_size,
							void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);

cipher_ctx *cipher_eax_decrypt_init(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *header, size_t header_size);
uint64_t cipher_eax_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_eax_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);
uint64_t cipher_eax_decrypt(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *header, size_t header_size,
							void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

// Synthetic Initialization Vector (SIV)

typedef struct _siv_ctx
{
	cipher_ctx *cp_ctx;
	// cmac_ctx *cm_ctx;
} siv_ctx;

siv_ctx *cipher_siv_cmac_init(cipher_algorithm algorithm, void *key, size_t key_size);
uint32_t cipher_siv_cmac_encrypt(siv_ctx *sctx, void *associated_data, size_t ad_size, void *plaintext, size_t plaintext_size,
								 void *ciphertext, size_t ciphertext_size);
uint32_t cipher_siv_cmac_decrypt(siv_ctx *sctx, void *associated_data, size_t ad_size, void *ciphertext, size_t ciphertext_size,
								 void *plaintext, size_t plaintext_size);

// AES-ECB
uint64_t aes128_ecb_encrypt(void *key, size_t key_size, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size,
							cipher_padding padding);
uint64_t aes128_ecb_decrypt(void *key, size_t key_size, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size,
							cipher_padding padding);

uint64_t aes192_ecb_encrypt(void *key, size_t key_size, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size,
							cipher_padding padding);
uint64_t aes192_ecb_decrypt(void *key, size_t key_size, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size,
							cipher_padding padding);

uint64_t aes256_ecb_encrypt(void *key, size_t key_size, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size,
							cipher_padding padding);
uint64_t aes256_ecb_decrypt(void *key, size_t key_size, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size,
							cipher_padding padding);

// AES-CBC
uint64_t aes128_cbc_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size, cipher_padding padding);
uint64_t aes128_cbc_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size, cipher_padding padding);

uint64_t aes192_cbc_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size, cipher_padding padding);
uint64_t aes192_cbc_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size, cipher_padding padding);

uint64_t aes256_cbc_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size, cipher_padding padding);
uint64_t aes256_cbc_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size, cipher_padding padding);

// AES-OFB
uint64_t aes128_ofb_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size);
uint64_t aes128_ofb_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size);

uint64_t aes192_ofb_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size);
uint64_t aes192_ofb_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size);

uint64_t aes256_ofb_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size);
uint64_t aes256_ofb_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size);



#endif
