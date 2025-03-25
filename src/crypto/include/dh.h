/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DH_H
#define CRYPTO_DH_H

#include <crypt.h>
#include <bignum.h>

typedef enum _dh_safe_prime_id
{
	// MODP
	MODP_1536 = 1,
	MODP_2048,
	MODP_3072,
	MODP_4096,
	MODP_6144,
	MODP_8192,

	// Small Subgroup
	MODP_1024_160,
	MODP_2048_224,
	MODP_2048_256,

	// FFDHE
	FFDHE_2048,
	FFDHE_3072,
	FFDHE_4096,
	FFDHE_6144,
	FFDHE_8192,

} dh_safe_prime_id;

typedef struct _dh_key
{
	uint16_t p_bits, q_bits;
	bignum_t *p, *q, *g;
	bignum_t *x, *y;
	bignum_t *mu;
	bignum_ctx *bctx;
} dh_key;

#endif
