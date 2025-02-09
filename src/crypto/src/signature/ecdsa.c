/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <ecdsa.h>

#include <bignum.h>
#include <hash.h>
#include <bignum-internal.h>

#include <stdlib.h>
#include <string.h>

ecdsa_signature *ecdsa_sign(ec_key *key, void *salt, size_t salt_size, void *hash, size_t hash_size, void *signature, size_t signature_size)
{
	ecdsa_signature *ecsign = signature;
	bignum_ctx *bctx = key->eg->bctx;

	size_t ctx_size = 5 * bignum_size(key->eg->bits);
	size_t required_signature_size = sizeof(ecdsa_signature) + (2 * bignum_size(key->eg->bits));

	bignum_t *k = NULL;
	bignum_t *ik = NULL;
	bignum_t *e = NULL;
	bignum_t *x = NULL;
	bignum_t *y = NULL;

	byte_t hash_copy[64] = {0};

	ec_point r;
	void *result = NULL;

	// Allocate the signature
	if (ecsign == NULL)
	{
		ecsign = malloc(required_signature_size);
	}
	else
	{
		if (signature_size < required_signature_size)
		{
			return NULL;
		}
	}

	if (ecsign == NULL)
	{
		return NULL;
	}

	ecsign->r = PTR_OFFSET(ecsign, sizeof(ecdsa_signature));
	ecsign->s = PTR_OFFSET(ecsign, sizeof(ecdsa_signature) + bignum_size(key->eg->bits));

	ecsign->r = bignum_init(ecsign->r, bignum_size(key->eg->bits), key->eg->bits);
	ecsign->s = bignum_init(ecsign->s, bignum_size(key->eg->bits), key->eg->bits);

	bignum_ctx_start(bctx, ctx_size);

	k = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	ik = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

	x = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	y = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

	e = bignum_ctx_allocate_bignum(bctx, MIN(key->eg->bits, hash_size * 8));

	// Zero the lower hash bits for the partial byte
	memcpy(hash_copy, hash, hash_size);

	if (key->eg->bits % 8 != 0)
	{
		hash_copy[key->eg->bits / 8] &= 0xFF - ((1 << (8 - key->eg->bits % 8)) - 1);
	}

	e = bignum_set_bytes_be(e, hash_copy, MIN(key->eg->bits / 8, hash_size));

retry:
	if (salt != NULL)
	{
		k = bignum_set_bytes_be(k, salt, salt_size);
	}
	else
	{
		k = bignum_rand_max(NULL, k, key->eg->n);
	}

	ik = bignum_modinv(bctx, ik, k, key->eg->n);

	// r = [k]G.
	r.x = x;
	r.y = y;

	result = ec_point_multiply(key->eg, &r, key->eg->g, k);

	if (result == NULL)
	{
		if (salt != NULL)
		{
			bignum_ctx_end(bctx);
			return NULL;
		}

		goto retry;
	}

	bignum_copy(ecsign->r, r.x);

	// s = (ik(e + rd)) mod n.
	ecsign->s = bignum_modmul(bctx, ecsign->s, ecsign->r, key->d, key->eg->n);
	ecsign->s = bignum_modadd(bctx, ecsign->s, ecsign->s, e, key->eg->n);
	ecsign->s = bignum_modmul(bctx, ecsign->s, ecsign->s, ik, key->eg->n);

	bignum_ctx_end(bctx);

	return ecsign;
}

uint32_t ecdsa_verify(ec_key *key, ecdsa_signature *ecsign, void *hash, size_t hash_size)
{
	uint32_t status = 0;
	bignum_ctx *bctx = key->eg->bctx;

	size_t ctx_size = 10 * bignum_size(key->eg->bits);

	bignum_t *is = NULL;
	bignum_t *u = NULL;
	bignum_t *v = NULL;
	bignum_t *e = NULL;

	bignum_t *x1 = NULL;
	bignum_t *y1 = NULL;

	bignum_t *x2 = NULL;
	bignum_t *y2 = NULL;

	bignum_t *x3 = NULL;
	bignum_t *y3 = NULL;

	ec_point r1, r2, r3;
	void *result = NULL;

	byte_t hash_copy[64] = {0};

	if (bignum_cmp(ecsign->r, key->eg->n) >= 0 || bignum_cmp(ecsign->s, key->eg->n) >= 0)
	{
		return 0;
	}

	bignum_ctx_start(bctx, ctx_size);

	is = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	u = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	v = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

	x1 = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	y1 = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

	x2 = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	y2 = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

	x3 = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	y3 = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

	e = bignum_ctx_allocate_bignum(bctx, MIN(key->eg->bits, hash_size * 8));

	// Zero the lower hash bits for the partial byte
	memcpy(hash_copy, hash, hash_size);

	if (key->eg->bits % 8 != 0)
	{
		hash_copy[key->eg->bits / 8] &= 0xFF - ((1 << (8 - key->eg->bits % 8)) - 1);
	}

	e = bignum_set_bytes_be(e, hash_copy, MIN(key->eg->bits / 8, hash_size));

	is = bignum_modinv(bctx, is, ecsign->s, key->eg->n);

	u = bignum_modmul(bctx, u, e, is, key->eg->n);
	v = bignum_modmul(bctx, v, ecsign->r, is, key->eg->n);

	// r = [u]G + [v]Q.
	r1.x = x1;
	r1.y = y1;

	result = ec_point_multiply(key->eg, &r1, key->eg->g, u);

	if (result == NULL)
	{
		goto end;
	}

	r2.x = x2;
	r2.y = y2;

	result = ec_point_multiply(key->eg, &r1, key->q, v);

	if (result == NULL)
	{
		goto end;
	}

	r3.x = x3;
	r3.y = y3;

	result = ec_point_add(key->eg, &r3, &r1, &r2);

	if (result == NULL)
	{
		goto end;
	}

	if (bignum_cmp(r3.x, ecsign->r) == 0)
	{
		status = 1;
	}

end:
	bignum_ctx_end(bctx);

	return status;
}
