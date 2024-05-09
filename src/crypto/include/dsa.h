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

dsa_key *dsa_generate_key(uint32_t bits);
void dsa_delete_key(dsa_key *key);

dsa_ctx *dsa_sign_init(dsa_key *key, hash_ctx *hctx);
void dsa_sign_free(dsa_ctx *dctx);
void dsa_sign_reset(dsa_ctx *dctx, dsa_key *key, hash_ctx *hctx);
void dsa_sign_update(dsa_ctx *dctx, void *message, size_t size);
dsa_signature *dsa_sign_final(dsa_ctx *dctx);
dsa_signature *dsa_sign(dsa_key *key, hash_ctx *hctx, void *message, size_t size);

dsa_ctx *dsa_verify_init(dsa_key *key, hash_ctx *hctx);
void dsa_verify_free(dsa_ctx *dctx);
void dsa_verify_reset(dsa_ctx *dctx, dsa_key *key, hash_ctx *hctx);
void dsa_verify_update(dsa_ctx *dctx, void *message, size_t size);
int32_t dsa_verify_final(dsa_ctx *dctx, dsa_signature *dsign);
int32_t dsa_verify(dsa_key *key, hash_ctx *hctx, void *message, size_t size, dsa_signature *dsign);

#endif
