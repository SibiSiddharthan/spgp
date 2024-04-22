/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include <bignum.h>
#include <types.h>

typedef struct _rsa_key
{
	uint32_t bits;
	bignum_t *p, *q, *n;
	bignum_t *d, *e;
} rsa_key;

typedef struct _oaep_options
{
	void *hash;
	void *mask;
} oaep_options;

typedef struct _rsa_signature
{
	bignum_t sign;
} rsa_signature;

rsa_key *rsa_generate_key(uint32_t bits);
void rsa_delete_key(rsa_key *key);

int32_t rsa_public_encrypt(rsa_key *key, bignum_t *plain, bignum_t *cipher);
int32_t rsa_public_decrypt(rsa_key *key, bignum_t *cipher, bignum_t *plain);

int32_t rsa_private_encrypt(rsa_key *key, bignum_t *plain, bignum_t *cipher);
int32_t rsa_private_decrypt(rsa_key *key, bignum_t *cipher, bignum_t *plain);

int32_t rsaes_encrypt_oaep(rsa_key *key, byte_t *plaintext, size_t plaintext_size, byte_t *label, size_t label_size, byte_t *ciphertext,
						   size_t ciphertext_size);
int32_t rsaes_decrypt_oaep(rsa_key *key, byte_t *plaintext, size_t plaintext_size, byte_t *label, size_t label_size, byte_t *ciphertext,
						   size_t ciphertext_size);

rsa_signature *rsa_sign_pkcs(rsa_key *key, byte_t *message, size_t size);
int32_t rsa_verify_pkcs(rsa_key *key, rsa_signature *signature, byte_t *message, size_t size);

rsa_signature *rsa_sign_pss(rsa_key *key, byte_t *message, size_t size);
int32_t rsa_verify_pss(rsa_key *key, rsa_signature *signature, byte_t *message, size_t size);

#endif
