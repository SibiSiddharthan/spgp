/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include <types.h>
#include <bignum.h>
#include <buffer.h>
#include <hash.h>

typedef struct _rsa_key
{
	uint32_t bits;
	bignum_t *p, *q, *n;
	bignum_t *d, *e;
} rsa_key;

typedef struct _mgf
{
	hash_ctx *hash;
	buffer_t *seed;
} mgf;

typedef struct _oaep_options
{
	hash_ctx *hash;
	mgf *mask;
} oaep_options;

typedef struct _rsa_signature
{
	bignum_t sign;
} rsa_signature;

rsa_key *rsa_generate_key(uint32_t bits);
void rsa_delete_key(rsa_key *key);

bignum_t *rsa_public_encrypt(rsa_key *key, bignum_t *plain);
bignum_t *rsa_public_decrypt(rsa_key *key, bignum_t *cipher);

bignum_t *rsa_private_encrypt(rsa_key *key, bignum_t *plain);
bignum_t *rsa_private_decrypt(rsa_key *key, bignum_t *cipher);

int32_t rsa_encrypt_oaep(rsa_key *key, buffer_t *plaintext, buffer_t *label, buffer_t *ciphertext, oaep_options *options);
int32_t rsa_decrypt_oaep(rsa_key *key, buffer_t *ciphertext, buffer_t *label, buffer_t *plaintext, oaep_options *options);

rsa_signature *rsa_sign_pkcs(rsa_key *key, byte_t *message, size_t size);
int32_t rsa_verify_pkcs(rsa_key *key, rsa_signature *signature, byte_t *message, size_t size);

rsa_signature *rsa_sign_pss(rsa_key *key, byte_t *message, size_t size);
int32_t rsa_verify_pss(rsa_key *key, rsa_signature *signature, byte_t *message, size_t size);

#endif
