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
	// Prime curves
	EC_NIST_P192 = 1,
	EC_NIST_P224 = 2,
	EC_NIST_P256 = 3,
	EC_NIST_P384 = 4,
	EC_NIST_P521 = 5,

	// Binary curves (Koblitz)
	EC_NIST_K163 = 6,
	EC_NIST_K233 = 7,
	EC_NIST_K283 = 8,
	EC_NIST_K409 = 9,
	EC_NIST_K571 = 10,

	// Binary curves (Psuedo random)
	EC_NIST_B163 = 11,
	EC_NIST_B233 = 12,
	EC_NIST_B283 = 13,
	EC_NIST_B409 = 14,
	EC_NIST_B571 = 15,

	// SECG
	EC_SECT_163K1 = EC_NIST_K163,
	EC_SECT_163R1 = 16,
	EC_SECT_163R2 = EC_NIST_B163,
	EC_SECT_193R1 = 17,
	EC_SECT_193R2 = 18,
	EC_SECT_233K1 = EC_NIST_K233,
	EC_SECT_233R1 = EC_NIST_B233,
	EC_SECT_239K1 = 19,
	EC_SECT_283K1 = EC_NIST_K283,
	EC_SECT_283R1 = EC_NIST_B283,
	EC_SECT_409K1 = EC_NIST_K409,
	EC_SECT_409R1 = EC_NIST_B409,
	EC_SECT_571K1 = EC_NIST_K571,
	EC_SECT_571R1 = EC_NIST_B571,
	EC_SECP_160K1 = 20,
	EC_SECP_160R1 = 21,
	EC_SECP_160R2 = 22,
	EC_SECP_192K1 = 23,
	EC_SECP_192R1 = EC_NIST_P192,
	EC_SECP_224K1 = 24,
	EC_SECP_224R1 = EC_NIST_P224,
	EC_SECP_256K1 = 25,
	EC_SECP_256R1 = EC_NIST_P256,
	EC_SECP_384R1 = EC_NIST_P384,
	EC_SECP_521R1 = EC_NIST_P521,

	// ANSI
	EC_ANSIT_163K1 = EC_SECT_163K1,
	EC_ANSIT_163R1 = EC_SECT_163R1,
	EC_ANSIT_163R2 = EC_SECT_163R2,
	EC_ANSIT_193R1 = EC_SECT_193R1,
	EC_ANSIT_193R2 = EC_SECT_193R2,
	EC_ANSIT_233K1 = EC_SECT_233K1,
	EC_ANSIT_233R1 = EC_SECT_233R1,
	EC_ANSIT_239K1 = EC_SECT_239K1,
	EC_ANSIT_283K1 = EC_SECT_283K1,
	EC_ANSIT_283R1 = EC_SECT_283R1,
	EC_ANSIT_409K1 = EC_SECT_409K1,
	EC_ANSIT_409R1 = EC_SECT_409R1,
	EC_ANSIT_571K1 = EC_SECT_571K1,
	EC_ANSIT_571R1 = EC_SECT_571R1,
	EC_ANSIP_160K1 = EC_SECP_160K1,
	EC_ANSIP_160R1 = EC_SECP_160R1,
	EC_ANSIP_160R2 = EC_SECP_160R2,
	EC_ANSIP_192K1 = EC_SECP_192K1,
	EC_ANSIP_192R1 = EC_SECP_192R1,
	EC_ANSIP_224K1 = EC_SECP_224K1,
	EC_ANSIP_224R1 = EC_SECP_224R1,
	EC_ANSIP_256K1 = EC_SECP_256K1,
	EC_ANSIP_256R1 = EC_SECP_256R1,
	EC_ANSIP_384R1 = EC_SECP_384R1,
	EC_ANSIP_521R1 = EC_SECP_521R1,

	// Brainpool
	EC_BRAINPOOL_160R1 = 26,
	EC_BRAINPOOL_160T1 = 27,
	EC_BRAINPOOL_192R1 = 28,
	EC_BRAINPOOL_192T1 = 29,
	EC_BRAINPOOL_224R1 = 30,
	EC_BRAINPOOL_224T1 = 31,
	EC_BRAINPOOL_256R1 = 32,
	EC_BRAINPOOL_256T1 = 33,
	EC_BRAINPOOL_320R1 = 34,
	EC_BRAINPOOL_320T1 = 35,
	EC_BRAINPOOL_384R1 = 36,
	EC_BRAINPOOL_384T1 = 37,
	EC_BRAINPOOL_512R1 = 38,
	EC_BRAINPOOL_512T1 = 39,

	// Special
	EC_X25519 = 40,
	EC_X448 = 41,

	// Twisted Edwards
	EC_ED25519 = 42,
	EC_ED448 = 43

} curve_id;

// y^2 = (x^3 + Ax + B) % p
typedef struct _ec_prime_curve
{
	// prime
	bignum_t *p;

	// constants
	bignum_t *a;
	bignum_t *b;

	// generator
	bignum_t *gx;
	bignum_t *gy;
} ec_prime_curve;

typedef struct _ec_point
{
	bignum_t *x, *y;
} ec_point;

typedef struct _ec_group
{
	curve_id id;

	void *parameters;
	bignum_ctx *bctx;

	bignum_t (*_add)(struct _ec_group *, struct _ec_point *, struct _ec_point *, struct _ec_point *);
	bignum_t (*_double)(struct _ec_group *, struct _ec_point *, struct _ec_point *);
	bignum_t (*_multiply)(struct _ec_group *, struct _ec_point *, struct _ec_point *, bignum_t *);
	bignum_t (*_check)(struct _ec_group *, struct _ec_point *);

} ec_group;

size_t ec_group_size(uint32_t bits);
uint32_t ec_group_bits(curve_id id);

ec_group *ec_group_init(void *ptr, size_t size, curve_id id);
ec_group *ec_group_new(curve_id id);
void ec_group_delete(ec_group *eg);

inline size_t ec_point_size(uint32_t bits)
{
	return sizeof(ec_point) + (2 * bignum_size(bits));
}

ec_point *ec_point_init(void *ptr, size_t size, curve_id id);
ec_point *ec_point_new(curve_id id);
ec_point *ec_point_copy(ec_point *dst, ec_point *src);
void ec_point_delete(ec_point *ep);

ec_point *ec_point_add(ec_group *g, ec_point *r, ec_point *a, ec_point *b);
ec_point *ec_point_dbl(ec_group *g, ec_point *r, ec_point *a);
ec_point *ec_point_mul(ec_group *g, ec_point *r, ec_point *a, bignum_t *n);

uint32_t ec_point_check(bignum_ctx *bctx, ec_point *a);

#endif
