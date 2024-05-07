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

dsa_ctx *dsa_sign_init(dsa_key *key, hash_ctx *hctx)
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

dsa_signature *dsa_sign_free(dsa_ctx *dctx)
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

	bignum_t *k = NULL;
	bignum_t *l = NULL;
	bignum_t *z = NULL;

	byte_t hash[MAX_HASH_SIZE] = {0};

	dsign = (dsa_signature *)malloc(sizeof(dsa_signature));

	if (dsign == NULL)
	{
		return NULL;
	}

	hash_final(dctx->hctx, hash, hctx->hash_size);
	k = bignum_new_rand(key->q->bits);

	dsign->r = bignum_modexp(key->g, k, key->p);
	dsign->r = bignum_mod(dsign->r, key->q);

	z = bignum_new(MIN(key->q->bits, hctx->hash_size * 8));
	bignum_set_bytes_be(z, hash, MIN(key->q->bits / 8, hctx->hash_size));

	dsign->s = bignum_modmul(key->x, dsign->r, key->q);
	dsign->s = bignum_modadd(dsign->s, z, key->q);
	l = bignum_modinv(k, key->q);
	dsign->s = bignum_modmull(dsign->s, l, key->q);

	bignum_secure_free(k);
	bignum_secure_free(l);
	bignum_secure_free(z);

	return dsign;
}

dsa_signature *dsa_sign(dsa_key *key, hash_ctx *hctx, void *message, size_t size)
{
	dsa_ctx *dctx = dsa_sign_init(key, hctx);
	dsa_signature *dsign = NULL;

	if (dctx == NULL)
	{
		return NULL;
	}

	dsa_sign_update(dctx, message, size);
	dsign = dsa_sign_final(dctx);

	dsa_sign_free(dctx);

	return dsign;
}

dsa_ctx *dsa_verify_init(dsa_key *key, hash_ctx *hctx)
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

dsa_signature *dsa_verify_free(dsa_ctx *dctx)
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
	int32_t status = -1;

	dsa_key *key = dctx->key;
	hash_ctx *hctx = dctx->hctx;

	bignum_t *w = NULL;
	bignum_t *v = NULL;
	bignum_t *z = NULL;

	bignum_t *u1 = NULL;
	bignum_t *u2 = NULL;
	bignum_t *u3 = NULL;
	bignum_t *u4 = NULL;

	byte_t hash[MAX_HASH_SIZE] = {0};

	if (bignum_cmp(dsign->r, key->q) >= 0 || bignum_cmp(dsign->s, key->q) >= 0)
	{
		return -1;
	}

	hash_final(dctx->hctx, hash, hctx->hash_size);

	w = bignum_modinv(dsign->s, key->q);

	z = bignum_new(MIN(key->q->bits, hctx->hash_size * 8));
	bignum_set_bytes_be(z, hash, MIN(key->q->bits / 8, hctx->hash_size));

	u1 = bignum_modmul(z, w, key->q);
	u2 = bignum_modmul(dsign->r, w, key->q);
	u3 = bignum_modexp(key->g, u1, key->p);
	u4 = bignum_modexp(key->y, u2, key->p);

	v = bignum_modmul(u3, u4, key->q);

	if (bignum_cmp(v, dsign->r) == 0)
	{
		status = 0;
	}

	bignum_secure_free(w);
	bignum_secure_free(v);
	bignum_secure_free(z);

	bignum_secure_free(u1);
	bignum_secure_free(u2);
	bignum_secure_free(u3);
	bignum_secure_free(u4);

	return status;
}

int32_t dsa_verify(dsa_key *key, hash_ctx *hctx, void *message, size_t size, dsa_signature *dsign)
{
	int32_t status = -1;
	dsa_ctx *dctx = dsa_verify_init(key, hctx);

	if (dctx == NULL)
	{
		return status;
	}

	dsa_verify_update(dctx, message, size);
	status = dsa_verify_final(dctx, dsign);

	dsa_verify_free(dctx);

	return status;
}
