/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <types.h>
#include <minmax.h>
#include <bignum.h>
#include <hash.h>
#include <dsa.h>
#include <bignum-internal.h>

dsa_ctx *dsa_sign_new(dsa_key *key, hash_ctx *hctx)
{
	dsa_ctx *dctx = NULL;

	dctx = (dsa_ctx *)malloc(sizeof(dsa_ctx));

	if (dctx == NULL)
	{
		return NULL;
	}

	dctx->key = key;
	dctx->hctx = hctx;

	hash_reset(dctx->hctx);

	return dctx;
}

void dsa_sign_delete(dsa_ctx *dctx)
{
	dctx->key = NULL;
	dctx->hctx = NULL;

	free(dctx);
}

void dsa_sign_reset(dsa_ctx *dctx, dsa_key *key, hash_ctx *hctx)
{
	dctx->key = key;
	dctx->hctx = hctx;

	hash_reset(dctx->hctx);
}

void dsa_sign_update(dsa_ctx *dctx, void *message, size_t size)
{
	hash_update(dctx->hctx, message, size);
}

dsa_signature *dsa_sign_final(dsa_ctx *dctx)
{
	dsa_signature *dsign = NULL;

	dsa_key *key = dctx->key;
	hash_ctx *hctx = dctx->hctx;
	bignum_ctx *bctx = dctx->key->bctx;

	size_t hash_size = hctx->hash_size;
	size_t ctx_size = 3 * bignum_size(key->q->bits);

	bignum_t *k = NULL;
	bignum_t *ik = NULL;
	bignum_t *z = NULL;

	// Allocate the signature
	dsign = (dsa_signature *)malloc(sizeof(dsa_signature) + bignum_size(key->p->bits) + bignum_size(key->q->bits));

	if (dsign == NULL)
	{
		return NULL;
	}

	dsign->r = (bignum_t *)((byte_t *)dsign + sizeof(dsa_signature));
	dsign->s = (bignum_t *)((byte_t *)dsign + sizeof(dsa_signature) + bignum_size(key->p->bits));

	dsign->r = bignum_init(dsign->r, bignum_size(key->p->bits), key->p->bits);
	dsign->s = bignum_init(dsign->s, bignum_size(key->q->bits), key->q->bits);

	bignum_ctx_start(bctx, ctx_size);

	k = bignum_ctx_allocate_bignum(bctx, key->q->bits);
	ik = bignum_ctx_allocate_bignum(bctx, key->q->bits);
	z = bignum_ctx_allocate_bignum(bctx, MIN(key->q->bits, hash_size * 8));

	// Finish hashing
	hash_final(dctx->hctx, NULL, hash_size);
	z = bignum_set_bytes_be(z, (byte_t *)&(dctx->hctx->hash), MIN(key->q->bits / 8, hash_size));

	k = bignum_rand(k, NULL, key->q->bits);
	ik = bignum_modinv(bctx, ik, k, key->q);

	// r = (g^k mod p) mod q.
	dsign->r = bignum_modexp(bctx, dsign->r, key->g, k, key->p);
	dsign->r = bignum_mod(bctx, dsign->r, dsign->r, key->q);

	// s = (ik(z + xr)) mod q.
	dsign->s = bignum_modmul(bctx, dsign->s, key->x, dsign->r, key->q);
	dsign->s = bignum_modadd(bctx, dsign->s, dsign->s, z, key->q);
	dsign->s = bignum_modmul(bctx, dsign->s, dsign->s, ik, key->q);

	bignum_ctx_end(bctx);

	return dsign;
}

dsa_signature *dsa_sign(dsa_key *key, hash_ctx *hctx, void *message, size_t size)
{
	dsa_ctx *dctx = dsa_sign_new(key, hctx);
	dsa_signature *dsign = NULL;

	if (dctx == NULL)
	{
		return NULL;
	}

	dsa_sign_update(dctx, message, size);
	dsign = dsa_sign_final(dctx);

	dsa_sign_delete(dctx);

	return dsign;
}

dsa_ctx *dsa_verify_new(dsa_key *key, hash_ctx *hctx)
{
	dsa_ctx *dctx = NULL;

	dctx = (dsa_ctx *)malloc(sizeof(dsa_ctx));

	if (dctx == NULL)
	{
		return NULL;
	}

	dctx->key = key;
	dctx->hctx = hctx;

	hash_reset(dctx->hctx);

	return dctx;
}

void dsa_verify_delete(dsa_ctx *dctx)
{
	dctx->key = NULL;
	dctx->hctx = NULL;

	free(dctx);
}

void dsa_verify_reset(dsa_ctx *dctx, dsa_key *key, hash_ctx *hctx)
{
	dctx->key = key;
	dctx->hctx = hctx;

	hash_reset(dctx->hctx);
}

void dsa_verify_update(dsa_ctx *dctx, void *message, size_t size)
{
	hash_update(dctx->hctx, message, size);
}

int32_t dsa_verify_final(dsa_ctx *dctx, dsa_signature *dsign)
{
	dsa_key *key = dctx->key;
	hash_ctx *hctx = dctx->hctx;
	bignum_ctx *bctx = dctx->key->bctx;

	size_t hash_size = hctx->hash_size;
	size_t ctx_size = (4 * bignum_size(key->q->bits)) + (3 * bignum_size(key->p->bits));

	bignum_t *w = NULL;
	bignum_t *v = NULL;
	bignum_t *z = NULL;

	bignum_t *u1 = NULL;
	bignum_t *u2 = NULL;
	bignum_t *u3 = NULL;
	bignum_t *u4 = NULL;

	if (bignum_cmp(dsign->r, key->q) >= 0 || bignum_cmp(dsign->s, key->q) >= 0)
	{
		return -1;
	}

	bignum_ctx_start(bctx, ctx_size);

	w = bignum_ctx_allocate_bignum(bctx, key->q->bits);
	v = bignum_ctx_allocate_bignum(bctx, key->p->bits);
	z = bignum_ctx_allocate_bignum(bctx, MIN(key->q->bits, hash_size * 8));

	u1 = bignum_ctx_allocate_bignum(bctx, key->q->bits);
	u2 = bignum_ctx_allocate_bignum(bctx, key->q->bits);
	u3 = bignum_ctx_allocate_bignum(bctx, key->p->bits);
	u4 = bignum_ctx_allocate_bignum(bctx, key->p->bits);

	// Hashing
	hash_final(dctx->hctx, NULL, hash_size);
	z = bignum_set_bytes_be(z, (byte_t *)&(dctx->hctx->hash), MIN(key->q->bits / 8, hash_size));

	w = bignum_modinv(bctx, w, dsign->s, key->q);

	u1 = bignum_modmul(bctx, u1, z, w, key->q);
	u2 = bignum_modmul(bctx, u2, dsign->r, w, key->q);

	u3 = bignum_modexp(bctx, u3, key->g, u1, key->p);
	u4 = bignum_modexp(bctx, u4, key->y, u2, key->p);

	v = bignum_modmul(bctx, v, u3, u4, key->p);
	v = bignum_mod(bctx, v, v, key->q);

	bignum_ctx_end(bctx);

	if (bignum_cmp(v, dsign->r) == 0)
	{
		return 0;
	}

	return -1;
}

int32_t dsa_verify(dsa_key *key, hash_ctx *hctx, void *message, size_t size, dsa_signature *dsign)
{
	int32_t status = -1;
	dsa_ctx *dctx = dsa_verify_new(key, hctx);

	if (dctx == NULL)
	{
		return status;
	}

	dsa_verify_update(dctx, message, size);
	status = dsa_verify_final(dctx, dsign);

	dsa_verify_delete(dctx);

	return status;
}
