/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_EC_H
#define CRYPTO_EC_H

#include <crypt.h>
#include <bignum.h>

typedef enum _curve_id
{
	EC_CUSTOM = 0,

	// NIST
	// Prime curves
	EC_NIST_P192,
	EC_NIST_P224,
	EC_NIST_P256,
	EC_NIST_P384,
	EC_NIST_P521,

	// Binary curves (Koblitz)
	EC_NIST_K163,
	EC_NIST_K233,
	EC_NIST_K283,
	EC_NIST_K409,
	EC_NIST_K571,

	// Binary curves (Psuedo random)
	EC_NIST_B163,
	EC_NIST_B233,
	EC_NIST_B283,
	EC_NIST_B409,
	EC_NIST_B571,

	// SECG
	EC_SECP_160K1,
	EC_SECP_160R1,
	EC_SECP_160R2,
	EC_SECP_192K1,
	EC_SECP_192R1,
	EC_SECP_224K1,
	EC_SECP_224R1,
	EC_SECP_256K1,
	EC_SECP_256R1,
	EC_SECP_384R1,
	EC_SECP_521R1,
	EC_SECT_163K1,
	EC_SECT_163R1,
	EC_SECT_163R2,
	EC_SECT_193R1,
	EC_SECT_193R2,
	EC_SECT_233K1,
	EC_SECT_233R1,
	EC_SECT_239K1,
	EC_SECT_283K1,
	EC_SECT_283R1,
	EC_SECT_409K1,
	EC_SECT_409R1,
	EC_SECT_571K1,
	EC_SECT_571R1,

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

	// Montgomery
	EC_CURVE25519,
	EC_CURVE448,

	// Twisted Edwards
	EC_ED25519,
	EC_ED448

} curve_id;

// ANSI curve counterparts to SEC
#define EC_ANSIP_160K1 EC_SECP_160K1
#define EC_ANSIP_160R1 EC_SECP_160R1
#define EC_ANSIP_160R2 EC_SECP_160R2
#define EC_ANSIP_192K1 EC_SECP_192K1
#define EC_ANSIP_192R1 EC_SECP_192R1
#define EC_ANSIP_224K1 EC_SECP_224K1
#define EC_ANSIP_224R1 EC_SECP_224R1
#define EC_ANSIP_256K1 EC_SECP_256K1
#define EC_ANSIP_256R1 EC_SECP_256R1
#define EC_ANSIP_384R1 EC_SECP_384R1
#define EC_ANSIP_521R1 EC_SECP_521R1
#define EC_ANSIT_163K1 EC_SECT_163K1
#define EC_ANSIT_163R1 EC_SECT_163R1
#define EC_ANSIT_163R2 EC_SECT_163R2
#define EC_ANSIT_193R1 EC_SECT_193R1
#define EC_ANSIT_193R2 EC_SECT_193R2
#define EC_ANSIT_233K1 EC_SECT_233K1
#define EC_ANSIT_233R1 EC_SECT_233R1
#define EC_ANSIT_239K1 EC_SECT_239K1
#define EC_ANSIT_283K1 EC_SECT_283K1
#define EC_ANSIT_283R1 EC_SECT_283R1
#define EC_ANSIT_409K1 EC_SECT_409K1
#define EC_ANSIT_409R1 EC_SECT_409R1
#define EC_ANSIT_571K1 EC_SECT_571K1
#define EC_ANSIT_571R1 EC_SECT_571R1

// y^2 = (x^3 + Ax + B) % p
typedef struct _ec_prime_curve
{
	// constants
	bignum_t *a;
	bignum_t *b;
} ec_prime_curve;

// y^2 + xy = (x^3 + Ax^2 + B) % p
typedef struct _ec_binary_curve
{
	// constants
	bignum_t *a;
	bignum_t *b;
} ec_binary_curve;

// By^2 = (x^3 + Ax^2 + x) % p
typedef struct _ec_montgomery_curve
{
	// constants
	bignum_t *a;
	bignum_t *b;
} ec_montgomery_curve;

// Ax^2 + y^2 = (1 + Dx^2y^2) % p
typedef struct _ec_edwards_curve
{
	// constants
	bignum_t *a;
	bignum_t *d;
} ec_edwards_curve;

// Placeholder struct
typedef struct _ec_generic_parameters
{
	bignum_t *a;
	bignum_t *b;
} ec_generic_parameters;

typedef struct _ec_point
{
	bignum_t *x, *y;
} ec_point;

typedef struct _ec_group
{
	curve_id id;
	uint32_t bits;
	uint32_t cofactor;

	bignum_t *p; // prime
	bignum_t *n; // order

	ec_point *g; // generator

	union
	{
		ec_prime_curve *prime_parameters;
		ec_binary_curve *binary_parameters;
		ec_montgomery_curve *montgomery_parameters;
		ec_edwards_curve *edwards_parameters;
		ec_generic_parameters *parameters;
	};

	bignum_ctx *bctx;

	ec_point *(*_add)(struct _ec_group *, struct _ec_point *, struct _ec_point *, struct _ec_point *);
	ec_point *(*_double)(struct _ec_group *, struct _ec_point *, struct _ec_point *);
	ec_point *(*_multiply)(struct _ec_group *, struct _ec_point *, struct _ec_point *, bignum_t *);
	uint32_t (*_on_curve)(struct _ec_group *, struct _ec_point *);
	uint32_t (*_is_identity)(struct _ec_group *, struct _ec_point *);
	uint32_t (*_encode)(struct _ec_group *, struct _ec_point *, void *, uint32_t, uint32_t);
	ec_point *(*_decode)(struct _ec_group *, struct _ec_point *, void *, uint32_t);

} ec_group;

typedef struct _ec_key
{
	ec_group *eg;

	bignum_t *d; // Private
	ec_point *q; // Public
} ec_key;

uint32_t ec_group_bits(curve_id id);

ec_group *ec_group_new(curve_id id);
void ec_group_delete(ec_group *eg);

static inline size_t ec_point_size(uint32_t bits)
{
	return sizeof(ec_point) + (2 * bignum_size(bits));
}

uint32_t ec_curve_oid_size(curve_id id);
uint32_t ec_curve_encode_oid(curve_id id, void *buffer, uint32_t size);
curve_id ec_curve_decode_oid(void *oid, uint32_t size);

ec_point *ec_point_init(void *ptr, size_t size, curve_id id);
ec_point *ec_point_new(ec_group *eg);
ec_point *ec_point_copy(ec_point *dst, ec_point *src);
void ec_point_delete(ec_point *ep);

void ec_point_infinity(ec_group *g, ec_point *r);
void ec_point_identity(ec_group *g, ec_point *r);

ec_point *ec_point_add(ec_group *g, ec_point *r, ec_point *a, ec_point *b);
ec_point *ec_point_double(ec_group *g, ec_point *r, ec_point *a);
ec_point *ec_point_multiply(ec_group *g, ec_point *r, ec_point *a, bignum_t *n);

uint32_t ec_point_on_curve(ec_group *g, ec_point *a);
uint32_t ec_point_is_identity(ec_group *g, ec_point *a);

uint32_t ec_point_encode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size, uint32_t compression);
ec_point *ec_point_decode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size);

ec_key *ec_key_generate(ec_group *eg, bignum_t *d);
uint32_t ec_public_key_validate(ec_key *ek, uint32_t full);

ec_key *ec_key_new(ec_group *eg, bignum_t *d, ec_point *q);
void ec_key_delete(ec_key *ek);

#endif
