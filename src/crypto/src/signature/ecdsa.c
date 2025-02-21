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

	size_t ctx_size = 6 * bignum_size(key->eg->bits);
	size_t required_signature_size = sizeof(ecdsa_signature) + (2 * bignum_size(key->eg->bits));

	bignum_t *k = NULL, *ik = NULL;
	bignum_t *e = NULL;
	bignum_t *x = NULL, *y = NULL;
	bignum_t *r = NULL, *s = NULL;

	byte_t hash_copy[64] = {0};

	ec_point p = {0};
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

	ecsign->r.size = CEIL_DIV(key->eg->bits, 8);
	ecsign->s.size = CEIL_DIV(key->eg->bits, 8);

	ecsign->r.sign = PTR_OFFSET(ecsign, sizeof(ecdsa_signature));
	ecsign->s.sign = PTR_OFFSET(ecsign, sizeof(ecdsa_signature) + ecsign->r.size);

	bignum_ctx_start(bctx, ctx_size);

	k = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	ik = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

	x = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	y = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

	s = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

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
	p.x = x;
	p.y = y;

	result = ec_point_multiply(key->eg, &p, key->eg->g, k);

	if (result == NULL)
	{
		if (salt != NULL)
		{
			bignum_ctx_end(bctx);
			return NULL;
		}

		goto retry;
	}

	r = p.x;

	// s = (ik(e + rd)) mod n.
	s = bignum_modmul(bctx, s, r, key->d, key->eg->n);
	s = bignum_modadd(bctx, s, s, e, key->eg->n);
	s = bignum_modmul(bctx, s, s, ik, key->eg->n);

	ecsign->r.size = bignum_get_bytes_be(r, ecsign->r.sign, ecsign->r.size);
	ecsign->r.bits = r->bits;

	ecsign->s.size = bignum_get_bytes_be(s, ecsign->s.sign, ecsign->s.size);
	ecsign->s.bits = s->bits;

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

	bignum_t *r = NULL, *s = NULL;

	ec_point r1, r2, r3;
	void *result = NULL;

	byte_t hash_copy[64] = {0};

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

	r = bignum_ctx_allocate_bignum(bctx, key->eg->bits);
	s = bignum_ctx_allocate_bignum(bctx, key->eg->bits);

	e = bignum_ctx_allocate_bignum(bctx, MIN(key->eg->bits, hash_size * 8));

	r = bignum_set_bytes_be(r, ecsign->r.sign, ecsign->r.size);
	s = bignum_set_bytes_be(s, ecsign->s.sign, ecsign->s.size);

	// Initial checks
	if (bignum_cmp(r, key->eg->n) >= 0 || bignum_cmp(s, key->eg->n) >= 0)
	{
		return 0;
	}

	// Zero the lower hash bits for the partial byte
	memcpy(hash_copy, hash, hash_size);

	if (key->eg->bits % 8 != 0)
	{
		hash_copy[key->eg->bits / 8] &= 0xFF - ((1 << (8 - key->eg->bits % 8)) - 1);
	}

	e = bignum_set_bytes_be(e, hash_copy, MIN(key->eg->bits / 8, hash_size));

	is = bignum_modinv(bctx, is, s, key->eg->n);

	u = bignum_modmul(bctx, u, e, is, key->eg->n);
	v = bignum_modmul(bctx, v, r, is, key->eg->n);

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

	if (bignum_cmp(r3.x, r) == 0)
	{
		status = 1;
	}

end:
	bignum_ctx_end(bctx);

	return status;
}
