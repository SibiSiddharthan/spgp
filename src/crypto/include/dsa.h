/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DSA_H
#define CRYPTO_DSA_H

#include <crypt.h>
#include <bignum.h>
#include <hash.h>

typedef struct _dsa_key
{
	uint16_t p_bits, q_bits;
	bignum_t *p, *q, *g;
	bignum_t *x, *y;
	bignum_t *mu;
	bignum_ctx *bctx;
} dsa_key;

typedef struct _dsa_signature
{
	bignum_t *r, *s;
} dsa_signature;

typedef struct _dsa_ctx
{
	dsa_key *key;
	hash_ctx *hctx;
	byte_t *salt;
	size_t salt_size;
} dsa_ctx;

uint32_t dsa_parameters_generate(hash_ctx *hctx, bignum_t *p, bignum_t *q, bignum_t *g, uint32_t p_bits, uint32_t q_bits, void *seed,
								 size_t seed_size);
uint32_t dsa_parameters_validate(hash_ctx *hctx, bignum_t *p, bignum_t *q, bignum_t *g, uint32_t counter, void *seed, size_t seed_size);

dsa_key *dsa_key_generate(bignum_t *p, bignum_t *q, bignum_t *g);
dsa_key *dsa_key_new(uint32_t p_bits, uint32_t q_bits);
void dsa_key_delete(dsa_key *key);

dsa_ctx *dsa_sign_new(dsa_key *key, hash_ctx *hctx, void *salt, size_t salt_size);
void dsa_sign_delete(dsa_ctx *dctx);
void dsa_sign_reset(dsa_ctx *dctx, dsa_key *key, hash_ctx *hctx);
void dsa_sign_update(dsa_ctx *dctx, void *message, size_t size);
dsa_signature *dsa_sign_final(dsa_ctx *dctx, void *signature, size_t size);
dsa_signature *dsa_sign(dsa_key *key, hash_ctx *hctx, void *salt, size_t salt_size, void *message, size_t message_size, void *signature,
						size_t signature_size);

dsa_ctx *dsa_verify_new(dsa_key *key, hash_ctx *hctx);
void dsa_verify_delete(dsa_ctx *dctx);
void dsa_verify_reset(dsa_ctx *dctx, dsa_key *key, hash_ctx *hctx);
void dsa_verify_update(dsa_ctx *dctx, void *message, size_t size);
uint32_t dsa_verify_final(dsa_ctx *dctx, dsa_signature *dsign);
uint32_t dsa_verify(dsa_key *key, hash_ctx *hctx, void *message, size_t size, dsa_signature *dsign);

#endif
