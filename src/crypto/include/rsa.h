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

typedef struct _rsa_pss_ctx
{
	rsa_key *key;
	hash_ctx *hctx;
	mgf *mask;
} rsa_pss_ctx;

typedef struct _rsa_pkcs_ctx
{
	rsa_key *key;
	hash_ctx *hctx;
} rsa_pkcs_ctx;

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

int32_t rsa_encrypt_pkcs(rsa_key *key, buffer_t *plaintext, buffer_t *ciphertext);
int32_t rsa_decrypt_pkcs(rsa_key *key, buffer_t *ciphertext, buffer_t *plaintext);

rsa_pss_ctx *rsa_sign_pss_init(rsa_key *key, hash_ctx *hctx, mgf *mask);
void rsa_sign_pss_free(rsa_pss_ctx *rctx);
void rsa_sign_pss_reset(rsa_pss_ctx *rctx, rsa_key *key, hash_ctx *hctx, mgf *mask);
void rsa_sign_pss_update(rsa_pss_ctx *rctx, void *message, size_t size);
rsa_signature *rsa_sign_pss_final(rsa_pss_ctx *rctx);
rsa_signature *rsa_sign_pss(rsa_key *key, hash_ctx *hctx, mgf *mask, void *message, size_t size);

rsa_pss_ctx *rsa_verify_pss_init(rsa_key *key, hash_ctx *hctx, mgf *mask);
void rsa_verify_pss_free(rsa_pss_ctx *rctx);
void rsa_verify_pss_reset(rsa_pss_ctx *rctx, rsa_key *key, hash_ctx *hctx, mgf *mask);
void rsa_verify_pss_update(rsa_pss_ctx *rctx, void *message, size_t size);
int32_t rsa_verify_pss_final(rsa_pss_ctx *rctx, rsa_signature *rsign, rsa_signature *expected);
int32_t rsa_verify_pss(rsa_key *key, hash_ctx *hctx, mgf *mask, void *message, size_t size, rsa_signature *rsign, rsa_signature *expected);

rsa_pkcs_ctx *rsa_sign_pkcs_init(rsa_key *key, hash_ctx *hctx);
void rsa_sign_pkcs_free(rsa_pkcs_ctx *rctx);
void rsa_sign_pkcs_reset(rsa_pkcs_ctx *rctx, rsa_key *key, hash_ctx *hctx);
void rsa_sign_pkcs_update(rsa_pkcs_ctx *rctx, void *message, size_t size);
rsa_signature *rsa_sign_pkcs_final(rsa_pkcs_ctx *rctx);
rsa_signature *rsa_sign_pkcs(rsa_key *key, hash_ctx *hctx, void *message, size_t size);

rsa_pkcs_ctx *rsa_verify_pkcs_init(rsa_key *key, hash_ctx *hctx);
void rsa_verify_pkcs_free(rsa_pkcs_ctx *rctx);
void rsa_verify_pkcs_reset(rsa_pkcs_ctx *rctx, rsa_key *key, hash_ctx *hctx);
void rsa_verify_pkcs_update(rsa_pkcs_ctx *rctx, void *message, size_t size);
int32_t rsa_verify_pkcs_final(rsa_pkcs_ctx *rctx, rsa_signature *rsign, rsa_signature *expected);
int32_t rsa_verify_pkcs(rsa_key *key, hash_ctx *hctx, void *message, size_t size, rsa_signature *rsign, rsa_signature *expected);

#endif
