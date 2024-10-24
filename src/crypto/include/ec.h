/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_EC_H
#define CRYPTO_EC_H

#include <bignum.h>

typedef enum _curve_id
{
	EC_CUSTOM = 0,

	// NIST
	// Montgomery curves
	EC_NIST_P192,
	EC_NIST_P224,
	EC_NIST_P256,
	EC_NIST_P384,
	EC_NIST_P521,

	// Koblitz curves
	EC_NIST_K163,
	EC_NIST_K233,
	EC_NIST_K283,
	EC_NIST_K409,
	EC_NIST_K571,

	// Psuedo random curves
	EC_NIST_B163,
	EC_NIST_B233,
	EC_NIST_B283,
	EC_NIST_B409,
	EC_NIST_B571,

	// SECG
	EC_SECT_163K1 = EC_NIST_K163,
	EC_SECT_163R1,
	EC_SECT_163R2 = EC_NIST_B163,
	EC_SECT_193R1,
	EC_SECT_193R2,
	EC_SECT_233K1 = EC_NIST_K233,
	EC_SECT_233R1 = EC_NIST_B233,
	EC_SECT_239K1,
	EC_SECT_283K1 = EC_NIST_K283,
	EC_SECT_283R1 = EC_NIST_B283,
	EC_SECT_409K1 = EC_NIST_K409,
	EC_SECT_409R1 = EC_NIST_B409,
	EC_SECT_571K1 = EC_NIST_K571,
	EC_SECT_571R1 = EC_NIST_B571,
	EC_SECP_160K1,
	EC_SECP_160R1,
	EC_SECP_160R2,
	EC_SECP_192K1,
	EC_SECP_192R1 = EC_NIST_P192,
	EC_SECP_224K1,
	EC_SECP_224R1 = EC_NIST_P224,
	EC_SECP_256K1,
	EC_SECP_256R1 = EC_NIST_P256,
	EC_SECP_384R1 = EC_NIST_P384,
	EC_SECP_521R1,

	// Brainpool
	EC_BRAINPOOL_160R1,
	EC_BRAINPOOL_160T1,
	EC_BRAINPOOL_192R1,
	EC_BRAINPOOL_192T1,
	EC_BRAINPOOL_224R1,
	EC_BRAINPOOL_224T1,
	EC_BRAINPOOL_256R1,
	EC_BRAINPOOL_256T1,
	EC_BRAINPOOL_320R1,
	EC_BRAINPOOL_320T1,
	EC_BRAINPOOL_384R1,
	EC_BRAINPOOL_384T1,
	EC_BRAINPOOL_512R1,
	EC_BRAINPOOL_512T1,

	// Goldilocks
	EC_X25519,
	EC_X448

} curve_id;

typedef struct _ec_point
{
	curve_id id;
	bignum_t *x, *y;

	bignum_t (*_add)(bignum_ctx *, bignum_t *, bignum_t *, bignum_t *, bignum_t *, bignum_t *, bignum_t *);
	bignum_t (*_double)(bignum_ctx *, bignum_t *, bignum_t *, bignum_t *, bignum_t *);
	bignum_t (*_check)(bignum_ctx *, bignum_t *, bignum_t *);

} ec_point;

inline size_t ec_point_size(uint32_t bits)
{
	return sizeof(ec_point) + (2 * bignum_size(bits));
}

ec_point *ec_point_init(void *ptr, size_t size, curve_id id);
ec_point *ec_point_new(curve_id id);
ec_point *ec_point_copy(ec_point *dst_p, ec_point *src_p);
ec_point *bignum_dup(bignum_ctx *bctx, ec_point *p);
void ec_point_delete(ec_point *bn);

ec_point *ec_point_add(bignum_ctx *bctx, ec_point *r, ec_point *a, ec_point *b);
ec_point *ec_point_dbl(bignum_ctx *bctx, ec_point *r, ec_point *a);
ec_point *ec_point_mul(bignum_ctx *bctx, ec_point *r, ec_point *a, bignum_t *n);

uint32_t ec_point_check(bignum_ctx *bctx, ec_point *a);

#endif
