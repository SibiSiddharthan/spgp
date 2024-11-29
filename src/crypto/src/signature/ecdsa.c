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
	ec_prime_curve *parameters = ectx->key->eg->parameters;
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

	ec_point r, g;
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

	if (key->eg->bits % 8 == 0)
	{
		e = bignum_set_bytes_be(e, ectx->hctx->hash, MIN(key->eg->bits / 8, hash_size));
	}
	else
	{
		// Zero the lower hash bits for the partial byte
		ectx->hctx->hash[key->eg->bits / 8] &= 0xFF - ((1 << (8 - key->eg->bits % 8)) - 1);
	}

retry:
	if (ectx->salt != NULL)
	{
		k = bignum_set_bytes_be(k, ectx->salt, ectx->salt_size);
	}
	else
	{
		k = bignum_rand(k, NULL, key->eg->bits);
	}

	ik = bignum_modinv(bctx, ik, k, parameters->n);

	// r = [k]G.
	r.x = x;
	r.y = y;

	g.x = parameters->gx;
	g.y = parameters->gy;

	result = ec_point_multiply(key->eg, &r, &g, k);

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
	ecsign->s = bignum_modmul(bctx, ecsign->s, ecsign->r, key->d, parameters->n);
	ecsign->s = bignum_modadd(bctx, ecsign->s, ecsign->s, e, parameters->n);
	ecsign->s = bignum_modmul(bctx, ecsign->s, ecsign->s, ik, parameters->n);

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

