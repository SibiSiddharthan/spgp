/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <dsa.h>

#include <bignum.h>
#include <hash.h>
#include <sha.h>
#include <drbg.h>
#include <bignum-internal.h>

#include <stdlib.h>
#include <string.h>

static uint32_t dsa_valid_pq_lengths(uint32_t p_bits, uint32_t q_bits)
{
	if (p_bits == 1024)
	{
		if (q_bits != 160)
		{
			return 0;
		}
	}
	else if (p_bits == 2048)
	{
		if (q_bits != 224 && q_bits != 256)
		{
			return 0;
		}
	}
	else if (p_bits == 3072)
	{
		if (q_bits != 256)
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}

	return 1;
}

dsa_key *dsa_key_generate(bignum_t *p, bignum_t *q, bignum_t *g)
{
	dsa_key *key = NULL;

	// Check bits
	if (dsa_valid_pq_lengths(p->bits, q->bits) == 0)
	{
		return NULL;
	}

	if (bignum_cmp(g, p) >= 0)
	{
		return NULL;
	}

	key = dsa_key_new(p->bits, q->bits);

	if (key == NULL)
	{
		return NULL;
	}

	// Copy the parameters
	bignum_copy(key->p, p);
	bignum_copy(key->q, q);
	bignum_copy(key->g, g);

	// Generate x
	bignum_rand_max(NULL, key->x, key->q);

	// Calculate y
	bignum_modexp(key->bctx, key->y, key->g, key->x, key->p);

	return key;
}

dsa_key *dsa_key_new(uint32_t p_bits, uint32_t q_bits)
{
	dsa_key *key = NULL;
	uint32_t bctx_size = 0;

	p_bits = ROUND_UP(p_bits, 1024);
	q_bits = ROUND_UP(q_bits, 8);

	if (dsa_valid_pq_lengths(p_bits, q_bits) == 0)
	{
		return NULL;
	}

	bctx_size += 16 * (p_bits * 2) / 8; // For bctx

	key = malloc(sizeof(dsa_key));

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, sizeof(dsa_key));

	key->p_bits = p_bits;
	key->q_bits = q_bits;

	key->bctx = bignum_ctx_new(bctx_size);

	if (key->bctx == NULL)
	{
		free(key);
		return NULL;
	}

	return key;
}

void dsa_key_delete(dsa_key *key)
{
	bignum_delete(key->p);
	bignum_delete(key->q);
	bignum_delete(key->g);

	bignum_delete(key->x);
	bignum_delete(key->y);

	bignum_delete(key->mu);

	bignum_ctx_delete(key->bctx);

	free(key);
}

dsa_signature *dsa_signature_new(dsa_key *key)
{
	dsa_signature *sign = malloc(sizeof(dsa_signature) + (2 * (key->q_bits / 8)));

	if (sign == NULL)
	{
		return NULL;
	}

	memset(sign, 0, sizeof(dsa_signature) + (2 * (key->q_bits / 8)));

	sign->r.bits = 0;
	sign->r.size = key->q_bits / 8;
	sign->r.sign = PTR_OFFSET(sign, sizeof(dsa_signature));

	sign->s.bits = 0;
	sign->s.size = key->q_bits / 8;
	sign->s.sign = PTR_OFFSET(sign, sizeof(dsa_signature) + (key->q_bits / 8));

	return sign;
}

void dsa_signature_delete(dsa_signature *sign)
{
	free(sign);
}

dsa_signature *dsa_sign(dsa_key *key, dsa_signature *dsign, void *salt, size_t salt_size, void *hash, size_t hash_size)
{
	size_t ctx_size = (5 * bignum_size(key->q->bits)) + bignum_size(key->p->bits);

	bignum_t *k = NULL, *ik = NULL;
	bignum_t *z = NULL, *t = NULL;
	bignum_t *r = NULL, *s = NULL;

	if (dsign->r.size < (key->q_bits / 8) || dsign->s.size < (key->q_bits / 8))
	{
		return NULL;
	}

	bignum_ctx_start(key->bctx, ctx_size);

	k = bignum_ctx_allocate_bignum(key->bctx, key->q->bits);
	ik = bignum_ctx_allocate_bignum(key->bctx, key->q->bits);
	r = bignum_ctx_allocate_bignum(key->bctx, key->q->bits);
	s = bignum_ctx_allocate_bignum(key->bctx, key->q->bits);
	z = bignum_ctx_allocate_bignum(key->bctx, MIN(key->q->bits, hash_size * 8));

	t = bignum_ctx_allocate_bignum(key->bctx, key->p->bits);

	// Finish hashing
	z = bignum_set_bytes_be(z, hash, MIN(key->q->bits / 8, hash_size));

	if (salt != NULL)
	{
		k = bignum_set_bytes_be(k, salt, salt_size);
	}
	else
	{
		k = bignum_rand_max(NULL, k, key->q);
	}

	ik = bignum_modinv(key->bctx, ik, k, key->q);

	// r = (g^k mod p) mod q.
	t = bignum_modexp(key->bctx, t, key->g, k, key->p);
	r = bignum_mod(key->bctx, r, t, key->q);

	// s = (ik(z + xr)) mod q.
	s = bignum_modmul(key->bctx, s, key->x, r, key->q);
	s = bignum_modadd(key->bctx, s, s, z, key->q);
	s = bignum_modmul(key->bctx, s, s, ik, key->q);

	// Load the signature
	bignum_get_bytes_be(r, dsign->r.sign, dsign->r.size);
	dsign->r.bits = r->bits;

	bignum_get_bytes_be(s, dsign->s.sign, dsign->s.size);
	dsign->s.bits = s->bits;

	bignum_ctx_end(key->bctx);

	return dsign;
}

uint32_t dsa_verify(dsa_key *key, dsa_signature *dsign, void *hash, size_t hash_size)
{
	uint32_t status = 0;
	size_t ctx_size = (6 * bignum_size(key->q->bits)) + (3 * bignum_size(key->p->bits));

	bignum_t *w = NULL;
	bignum_t *v = NULL;
	bignum_t *z = NULL;
	bignum_t *r = NULL, *s = NULL;

	bignum_t *u1 = NULL;
	bignum_t *u2 = NULL;
	bignum_t *u3 = NULL;
	bignum_t *u4 = NULL;

	bignum_ctx_start(key->bctx, ctx_size);

	w = bignum_ctx_allocate_bignum(key->bctx, key->q->bits);
	v = bignum_ctx_allocate_bignum(key->bctx, key->p->bits);
	r = bignum_ctx_allocate_bignum(key->bctx, key->q->bits);
	s = bignum_ctx_allocate_bignum(key->bctx, key->q->bits);
	z = bignum_ctx_allocate_bignum(key->bctx, MIN(key->q->bits, hash_size * 8));

	u1 = bignum_ctx_allocate_bignum(key->bctx, key->q->bits);
	u2 = bignum_ctx_allocate_bignum(key->bctx, key->q->bits);
	u3 = bignum_ctx_allocate_bignum(key->bctx, key->p->bits);
	u4 = bignum_ctx_allocate_bignum(key->bctx, key->p->bits);

	r = bignum_set_bytes_be(r, dsign->r.sign, dsign->r.size);
	s = bignum_set_bytes_be(s, dsign->s.sign, dsign->s.size);

	// Initial checks
	if (bignum_cmp(r, key->q) >= 0 || bignum_cmp(s, key->q) >= 0)
	{
		goto end;
	}

	// Hashing
	z = bignum_set_bytes_be(z, hash, MIN(key->q->bits / 8, hash_size));

	w = bignum_modinv(key->bctx, w, s, key->q);

	u1 = bignum_modmul(key->bctx, u1, z, w, key->q);
	u2 = bignum_modmul(key->bctx, u2, r, w, key->q);

	u3 = bignum_modexp(key->bctx, u3, key->g, u1, key->p);
	u4 = bignum_modexp(key->bctx, u4, key->y, u2, key->p);

	v = bignum_modmul(key->bctx, v, u3, u4, key->p);
	v = bignum_mod(key->bctx, v, v, key->q);

	if (bignum_cmp(v, r) == 0)
	{
		status = 1;
	}

end:
	bignum_ctx_end(key->bctx);
	return status;
}
