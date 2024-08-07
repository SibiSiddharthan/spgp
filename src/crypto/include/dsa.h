/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DSA_H
#define CRYPTO_DSA_H

#include <types.h>
#include <bignum.h>
#include <hash.h>

typedef struct _dsa_key
{
	bignum_t *p, *q, *g;
	bignum_t *x, *y;
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
} dsa_ctx;

dsa_key *dsa_key_generate(uint32_t bits);
void dsa_key_new(dsa_key *key);
void dsa_key_delete(dsa_key *key);

dsa_ctx *dsa_sign_new(dsa_key *key, hash_ctx *hctx);
void dsa_sign_delete(dsa_ctx *dctx);
void dsa_sign_reset(dsa_ctx *dctx, dsa_key *key, hash_ctx *hctx);
void dsa_sign_update(dsa_ctx *dctx, void *message, size_t size);
dsa_signature *dsa_sign_final(dsa_ctx *dctx);
dsa_signature *dsa_sign(dsa_key *key, hash_ctx *hctx, void *message, size_t size);

dsa_ctx *dsa_verify_new(dsa_key *key, hash_ctx *hctx);
void dsa_verify_delete(dsa_ctx *dctx);
void dsa_verify_reset(dsa_ctx *dctx, dsa_key *key, hash_ctx *hctx);
void dsa_verify_update(dsa_ctx *dctx, void *message, size_t size);
int32_t dsa_verify_final(dsa_ctx *dctx, dsa_signature *dsign);
int32_t dsa_verify(dsa_key *key, hash_ctx *hctx, void *message, size_t size, dsa_signature *dsign);

#endif
