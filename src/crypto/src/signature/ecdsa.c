/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include <hash.h>
#include <ecdsa.h>
#include <bignum-internal.h>

#include <minmax.h>
#include <ptr.h>

ecdsa_ctx *ecdsa_sign_new(ec_key *key, hash_ctx *hctx, void *salt, size_t salt_size)
{
	ecdsa_ctx *ectx = NULL;

	if (salt != NULL && salt_size > (key->eg->bits))
	{
		return NULL;
	}

	ectx = (ecdsa_ctx *)malloc(sizeof(ecdsa_ctx));

	if (ectx == NULL)
	{
		return NULL;
	}

	ectx->key = key;
	ectx->hctx = hctx;
	ectx->salt = salt;
	ectx->salt_size = salt_size;

	hash_reset(ectx->hctx);

	return ectx;
}

void ecdsa_sign_delete(ecdsa_ctx *ectx)
{
	ectx->key = NULL;
	ectx->hctx = NULL;

	free(ectx);
}

void ecdsa_sign_reset(ecdsa_ctx *ectx, ec_key *key, hash_ctx *hctx)
{
	ectx->key = key;
	ectx->hctx = hctx;

	hash_reset(ectx->hctx);
}

void ecdsa_sign_update(ecdsa_ctx *ectx, void *message, size_t size)
{
	hash_update(ectx->hctx, message, size);
}

ecdsa_signature *ecdsa_sign_final(ecdsa_ctx *ectx, void *signature, size_t size)
{
	ecdsa_signature *ecsign = signature;

	ec_key *key = ectx->key;
	hash_ctx *hctx = ectx->hctx;
	bignum_ctx *bctx = ectx->key->eg->bctx;

	size_t hash_size = hctx->hash_size;
	size_t ctx_size = 5 * bignum_size(key->eg->bits);
	size_t signature_size = sizeof(ecdsa_signature) + (2 * bignum_size(key->eg->bits));

	bignum_t *k = NULL;
	bignum_t *ik = NULL;
	bignum_t *e = NULL;
	bignum_t *x = NULL;
	bignum_t *y = NULL;

	ec_point r;
	void *result = NULL;

	// Allocate the signature
	if (ecsign == NULL)
	{
		ecsign = malloc(signature_size);
	}
	else
	{
		if (size < signature_size)
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

	// Finish hashing
	hash_final(ectx->hctx, NULL, hash_size);

	if (key->eg->bits % 8 != 0)
	{
		// Zero the lower hash bits for the partial byte
		ectx->hctx->hash[key->eg->bits / 8] &= 0xFF - ((1 << (8 - key->eg->bits % 8)) - 1);
	}

	e = bignum_set_bytes_be(e, ectx->hctx->hash, MIN(key->eg->bits / 8, hash_size));

retry:
	if (ectx->salt != NULL)
	{
		k = bignum_set_bytes_be(k, ectx->salt, ectx->salt_size);
	}
	else
	{
		k = bignum_rand_max(NULL, k, key->eg->n);
	}

	ik = bignum_modinv(bctx, ik, k, ectx->key->eg->n);

	// r = [k]G.
	r.x = x;
	r.y = y;

	result = ec_point_multiply(key->eg, &r, ectx->key->eg->g, k);

	if (result == NULL)
	{
		if (ectx->salt != NULL)
		{
			bignum_ctx_end(bctx);
			return NULL;
		}

		goto retry;
	}

	bignum_copy(ecsign->r, r.x);

	// s = (ik(e + rd)) mod n.
	ecsign->s = bignum_modmul(bctx, ecsign->s, ecsign->r, key->d, ectx->key->eg->n);
	ecsign->s = bignum_modadd(bctx, ecsign->s, ecsign->s, e, ectx->key->eg->n);
	ecsign->s = bignum_modmul(bctx, ecsign->s, ecsign->s, ik, ectx->key->eg->n);

	bignum_ctx_end(bctx);

	return ecsign;
}

ecdsa_signature *ecdsa_sign(ec_key *key, hash_ctx *hctx, void *salt, size_t salt_size, void *message, size_t message_size, void *signature,
							size_t signature_size)
{
	ecdsa_ctx *ectx = ecdsa_sign_new(key, hctx, salt, salt_size);
	ecdsa_signature *dsign = NULL;

	if (ectx == NULL)
	{
		return NULL;
	}

	ecdsa_sign_update(ectx, message, message_size);
	dsign = ecdsa_sign_final(ectx, signature, signature_size);

	ecdsa_sign_delete(ectx);

	return dsign;
}

ecdsa_ctx *ecdsa_verify_new(ec_key *key, hash_ctx *hctx)
{
	ecdsa_ctx *ectx = NULL;

	ectx = (ecdsa_ctx *)malloc(sizeof(ecdsa_ctx));

	if (ectx == NULL)
	{
		return NULL;
	}

	ectx->key = key;
	ectx->hctx = hctx;

	hash_reset(ectx->hctx);

	return ectx;
}

void ecdsa_verify_delete(ecdsa_ctx *ectx)
{
	ectx->key = NULL;
	ectx->hctx = NULL;

	free(ectx);
}

void ecdsa_verify_reset(ecdsa_ctx *ectx, ec_key *key, hash_ctx *hctx)
{
	ectx->key = key;
	ectx->hctx = hctx;

	hash_reset(ectx->hctx);
}

void ecdsa_verify_update(ecdsa_ctx *ectx, void *message, size_t size)
{
	hash_update(ectx->hctx, message, size);
}

uint32_t ecdsa_verify_final(ecdsa_ctx *ectx, ecdsa_signature *ecsign)
{
	uint32_t status = 0;

	ec_key *key = ectx->key;
	hash_ctx *hctx = ectx->hctx;
	bignum_ctx *bctx = ectx->key->eg->bctx;

	size_t hash_size = hctx->hash_size;
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

	if (bignum_cmp(ecsign->r, ectx->key->eg->n) >= 0 || bignum_cmp(ecsign->s, ectx->key->eg->n) >= 0)
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

	// Hashing
	hash_final(ectx->hctx, NULL, hash_size);

	if (key->eg->bits % 8 != 0)
	{
		// Zero the lower hash bits for the partial byte
		ectx->hctx->hash[key->eg->bits / 8] &= 0xFF - ((1 << (8 - key->eg->bits % 8)) - 1);
	}

	e = bignum_set_bytes_be(e, ectx->hctx->hash, MIN(key->eg->bits / 8, hash_size));

	is = bignum_modinv(bctx, is, ecsign->s, ectx->key->eg->n);

	u = bignum_modmul(bctx, u, e, is, ectx->key->eg->n);
	v = bignum_modmul(bctx, v, ecsign->r, is, ectx->key->eg->n);

	// r = [u]G + [v]Q.
	r1.x = x1;
	r1.y = y1;

	result = ec_point_multiply(key->eg, &r1, ectx->key->eg->g, u);

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

uint32_t ecdsa_verify(ec_key *key, hash_ctx *hctx, void *message, size_t size, ecdsa_signature *dsign)
{
	uint32_t status = 0;
	ecdsa_ctx *ectx = ecdsa_verify_new(key, hctx);

	if (ectx == NULL)
	{
		return status;
	}

	ecdsa_verify_update(ectx, message, size);
	status = ecdsa_verify_final(ectx, dsign);

	ecdsa_verify_delete(ectx);

	return status;
}
