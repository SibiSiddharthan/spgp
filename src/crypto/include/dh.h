/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DH_H
#define CRYPTO_DH_H

#include <crypt.h>
#include <bignum.h>
#include <hash.h>

typedef enum _dh_safe_prime_id
{
	DH_CUSTOM = 0,

	// MODP
	DH_MODP_1024 = 1,
	DH_MODP_1536,
	DH_MODP_2048,
	DH_MODP_3072,
	DH_MODP_4096,
	DH_MODP_6144,
	DH_MODP_8192,

	// Small Subgroup
	DH_MODP_1024_160,
	DH_MODP_2048_224,
	DH_MODP_2048_256,

	// FFDHE
	DH_FFDHE_2048,
	DH_FFDHE_3072,
	DH_FFDHE_4096,
	DH_FFDHE_6144,
	DH_FFDHE_8192,

} dh_safe_prime_id;

typedef struct _dh_group
{
	dh_safe_prime_id id;
	uint32_t p_bits, q_bits;
	bignum_t *p, *q, *g;
	bignum_t *mu;
	bignum_ctx *bctx;
} dh_group;

typedef struct _dh_key
{
	dh_group *group;
	bignum_t *x, *y;
} dh_key;

dh_group *dh_group_new(dh_safe_prime_id id);
void dh_group_delete(dh_group *group);

uint32_t dh_group_generate(dh_group *group, hash_ctx *hctx, uint32_t p_bits, uint32_t q_bits, void *seed, size_t seed_size);
uint32_t dh_group_validate(dh_group *group, hash_ctx *hctx, uint32_t counter, void *seed, size_t seed_size);

dh_key *dh_key_new(dh_group *group, bignum_t *x, bignum_t *y);
void dh_key_delete(dh_key *key);
dh_key *dh_key_generate(dh_group *group);

#endif
