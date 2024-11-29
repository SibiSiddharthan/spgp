/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_ECDSA_H
#define CRYPTO_ECDSA_H

#include <bignum.h>
#include <ec.h>
#include <hash.h>

typedef struct _ecdsa_ctx
{
	ec_key *key;
	hash_ctx *hctx;
	byte_t *salt;
	size_t salt_size;
} ecdsa_ctx;

typedef struct _ecdsa_signature
{
	bignum_t *r, *s;
} ecdsa_signature;

ecdsa_ctx *ecdsa_sign_new(ec_key *key, hash_ctx *hctx, void *salt, size_t salt_size);
void ecdsa_sign_delete(ecdsa_ctx *dctx);
void ecdsa_sign_reset(ecdsa_ctx *dctx, ec_key *key, hash_ctx *hctx);
void ecdsa_sign_update(ecdsa_ctx *dctx, void *message, size_t size);
ecdsa_signature *ecdsa_sign_final(ecdsa_ctx *dctx, void *signature, size_t size);
ecdsa_signature *ecdsa_sign(ec_key *key, hash_ctx *hctx, void *salt, size_t salt_size, void *message, size_t message_size, void *signature,
							size_t signature_size);

ecdsa_ctx *ecdsa_verify_new(ec_key *key, hash_ctx *hctx);
void ecdsa_verify_delete(ecdsa_ctx *dctx);
void ecdsa_verify_reset(ecdsa_ctx *dctx, ec_key *key, hash_ctx *hctx);
void ecdsa_verify_update(ecdsa_ctx *dctx, void *message, size_t size);
uint32_t ecdsa_verify_final(ecdsa_ctx *dctx, ecdsa_signature *dsign);
uint32_t ecdsa_verify(ec_key *key, hash_ctx *hctx, void *message, size_t size, ecdsa_ctx *dsign);

#endif
