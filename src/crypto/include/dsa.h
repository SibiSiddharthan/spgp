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
	struct
	{
		uint32_t bits;
		uint32_t size;
		byte_t *sign;
	} r, s;
} dsa_signature;

uint32_t dsa_parameters_generate(hash_ctx *hctx, bignum_t *p, bignum_t *q, bignum_t *g, uint32_t p_bits, uint32_t q_bits, void *seed,
								 size_t seed_size);
uint32_t dsa_parameters_validate(hash_ctx *hctx, bignum_t *p, bignum_t *q, bignum_t *g, uint32_t counter, void *seed, size_t seed_size);

dsa_key *dsa_key_generate(bignum_t *p, bignum_t *q, bignum_t *g);
dsa_key *dsa_key_new(uint32_t p_bits, uint32_t q_bits);
void dsa_key_delete(dsa_key *key);

dsa_signature *dsa_sign(dsa_key *key, void *salt, size_t salt_size, void *hash, size_t hash_size, void *signature, size_t signature_size);
uint32_t dsa_verify(dsa_key *key, dsa_signature *dsign, void *hash, size_t hash_size);

#endif
