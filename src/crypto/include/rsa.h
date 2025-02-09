/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include <crypt.h>
#include <bignum.h>
#include <hash.h>
#include <drbg.h>

typedef struct _rsa_key
{
	uint32_t bits;
	bignum_t *p, *q, *n;
	bignum_t *d, *e;
	bignum_t *dmp1, *dmq1, *iqmp;
	bignum_t *mu;
	bignum_ctx *bctx;
} rsa_key;

typedef struct _rsa_pss_ctx
{
	rsa_key *key;
	hash_ctx *hctx_message;
	hash_ctx *hctx_mask;
	drbg_ctx *drbg;
	byte_t *salt;
	size_t salt_size;
} rsa_pss_ctx;

typedef struct _rsa_signature
{
	uint32_t bits;
	uint32_t size;
	byte_t *sign;
} rsa_signature;

rsa_key *rsa_key_generate(uint32_t bits, bignum_t *e);
rsa_key *rsa_key_new(uint32_t bits);
void rsa_key_delete(rsa_key *key);

uint32_t rsa_public_encrypt(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint32_t rsa_public_decrypt(rsa_key *key, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

uint32_t rsa_private_encrypt(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint32_t rsa_private_decrypt(rsa_key *key, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

uint32_t rsa_encrypt_oaep(rsa_key *key, hash_ctx *hctx_label, hash_ctx *hctx_mask, drbg_ctx *drbg, void *label, size_t label_size,
						  void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint32_t rsa_decrypt_oaep(rsa_key *key, hash_ctx *hctx_label, hash_ctx *hctx_mask, void *label, size_t label_size, void *ciphertext,
						  size_t ciphertext_size, void *plaintext, size_t plaintext_size);

uint32_t rsa_encrypt_pkcs(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size, drbg_ctx *drbg);
uint32_t rsa_decrypt_pkcs(rsa_key *key, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

rsa_signature *rsa_sign_pss(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, drbg_ctx *drbg, void *salt, size_t salt_size,
							void *message, size_t message_size, void *signature, size_t signature_size);
uint32_t rsa_verify_pss(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, size_t salt_size, void *message, size_t size,
						rsa_signature *rsign);

rsa_signature *rsa_sign_pkcs(rsa_key *key, hash_algorithm algorithm, void *hash, size_t hash_size, void *signature, size_t signature_size);
uint32_t rsa_verify_pkcs(rsa_key *key, rsa_signature *rsign, hash_algorithm algorithm, void *hash, size_t hash_size);

#endif
