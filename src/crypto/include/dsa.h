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
	uint32_t size;
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

dsa_key *dsa_key_generate(uint32_t bits);
dsa_key *dsa_key_new(uint32_t p_bits, uint32_t q_bits);
void dsa_key_delete(dsa_key *key);

dsa_key *dsa_key_set_pqg(dsa_key *key, bignum_t *p, bignum_t *q, bignum_t *g);
dsa_key *dsa_key_set_xy(dsa_key *key, bignum_t *x, bignum_t *y);

inline const bignum_t *dsa_key_get_p(dsa_key *key)
{
	return key->p;
}

inline const bignum_t *dsa_key_get_q(dsa_key *key)
{
	return key->q;
}

inline const bignum_t *dsa_key_get_g(dsa_key *key)
{
	return key->g;
}

inline const bignum_t *dsa_key_get_x(dsa_key *key)
{
	return key->x;
}

inline const bignum_t *dsa_key_get_y(dsa_key *key)
{
	return key->y;
}

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
