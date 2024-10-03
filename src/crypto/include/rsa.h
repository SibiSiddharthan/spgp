/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include <types.h>
#include <bignum.h>
#include <hash.h>
#include <drbg.h>

typedef struct _rsa_key
{
	uint32_t size;
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
	size_t salt_size;
} rsa_pss_ctx;

typedef struct _rsa_pkcs_ctx
{
	rsa_key *key;
	hash_ctx *hctx;
	uint32_t der_size;
} rsa_pkcs_ctx;

typedef struct _rsa_signature
{
	uint32_t bits;
	uint32_t size;
	byte_t *sign;
} rsa_signature;

rsa_key *rsa_key_generate(uint32_t bits);
rsa_key *rsa_key_new(uint32_t bits);
void rsa_key_delete(rsa_key *key);

void rsa_key_set_basic(rsa_key *key, bignum_t *n, bignum_t *d, bignum_t *e);
void rsa_key_set_factors(rsa_key *key, bignum_t *p, bignum_t *q);
void rsa_key_set_crt(rsa_key *key, bignum_t *dmp1, bignum_t *dmq1, bignum_t *iqmp);

inline const bignum_t *rsa_key_get_p(rsa_key *key)
{
	return key->p;
}

inline const bignum_t *rsa_key_get_q(rsa_key *key)
{
	return key->q;
}

inline const bignum_t *rsa_key_get_n(rsa_key *key)
{
	return key->n;
}

inline const bignum_t *rsa_key_get_d(rsa_key *key)
{
	return key->d;
}

inline const bignum_t *rsa_key_get_e(rsa_key *key)
{
	return key->e;
}

inline const bignum_t *rsa_key_get_dmp1(rsa_key *key)
{
	return key->dmp1;
}

inline const bignum_t *rsa_key_get_dmq1(rsa_key *key)
{
	return key->dmq1;
}

inline const bignum_t *rsa_key_get_iqmp(rsa_key *key)
{
	return key->iqmp;
}

uint32_t rsa_public_encrypt(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint32_t rsa_public_decrypt(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);

uint32_t rsa_private_encrypt(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint32_t rsa_private_decrypt(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);

int32_t rsa_encrypt_oaep(rsa_key *key, void *plaintext, size_t plaintext_size, void *label, size_t label_size, void *ciphertext,
						 size_t ciphertext_size, hash_ctx *hctx_label, hash_ctx *hctx_mask, drbg_ctx *drbg);
int32_t rsa_decrypt_oaep(rsa_key *key, void *ciphertext, size_t ciphertext_size, void *label, size_t label_size, void *plaintext,
						 size_t plaintext_size, hash_ctx *hctx_label, hash_ctx *hctx_mask);

int32_t rsa_encrypt_pkcs(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size, drbg_ctx *drbg);
int32_t rsa_decrypt_pkcs(rsa_key *key, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

rsa_pss_ctx *rsa_sign_pss_new(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, drbg_ctx *drbg, size_t salt_size);
void rsa_sign_pss_delete(rsa_pss_ctx *rctx);
void rsa_sign_pss_reset(rsa_pss_ctx *rctx, rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, drbg_ctx *drbg, size_t salt_size);
void rsa_sign_pss_update(rsa_pss_ctx *rctx, void *message, size_t size);
rsa_signature *rsa_sign_pss_final(rsa_pss_ctx *rctx);
rsa_signature *rsa_sign_pss(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, drbg_ctx *drbg, size_t salt_size, void *message,
							size_t message_size);

rsa_pss_ctx *rsa_verify_pss_new(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, size_t salt_size);
void rsa_verify_pss_delete(rsa_pss_ctx *rctx);
void rsa_verify_pss_reset(rsa_pss_ctx *rctx, rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, size_t salt_size);
void rsa_verify_pss_update(rsa_pss_ctx *rctx, void *message, size_t size);
int32_t rsa_verify_pss_final(rsa_pss_ctx *rctx, rsa_signature *rsign);
int32_t rsa_verify_pss(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, size_t salt_size, void *message, size_t size,
					   rsa_signature *rsign);

rsa_pkcs_ctx *rsa_sign_pkcs_new(rsa_key *key, hash_ctx *hctx);
void rsa_sign_pkcs_delete(rsa_pkcs_ctx *rctx);
void rsa_sign_pkcs_reset(rsa_pkcs_ctx *rctx, rsa_key *key, hash_ctx *hctx);
void rsa_sign_pkcs_update(rsa_pkcs_ctx *rctx, void *message, size_t size);
rsa_signature *rsa_sign_pkcs_final(rsa_pkcs_ctx *rctx);
rsa_signature *rsa_sign_pkcs(rsa_key *key, hash_ctx *hctx, void *message, size_t size);

rsa_pkcs_ctx *rsa_verify_pkcs_new(rsa_key *key, hash_ctx *hctx);
void rsa_verify_pkcs_delete(rsa_pkcs_ctx *rctx);
void rsa_verify_pkcs_reset(rsa_pkcs_ctx *rctx, rsa_key *key, hash_ctx *hctx);
void rsa_verify_pkcs_update(rsa_pkcs_ctx *rctx, void *message, size_t size);
int32_t rsa_verify_pkcs_final(rsa_pkcs_ctx *rctx, rsa_signature *rsign);
int32_t rsa_verify_pkcs(rsa_key *key, hash_ctx *hctx, void *message, size_t size, rsa_signature *rsign);

#endif
