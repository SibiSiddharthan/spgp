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

dsa_group *dsa_group_generate(uint32_t p_bits, uint32_t q_bits)
{
	byte_t buffer[1024] = {0};
	byte_t seed[64] = {0};

	drbg_ctx *drbg = NULL;
	hash_ctx *hctx = NULL;
	uint32_t seed_size = 0;

	// Check bits
	if (dsa_valid_pq_lengths(p_bits, q_bits) == 0)
	{
		return NULL;
	}

	drbg = get_default_drbg();
	hctx = hash_init(buffer, 1024, HASH_SHA256);

	if (drbg == NULL || hctx == NULL)
	{
		return NULL;
	}

	seed_size = drbg_generate(drbg, 0, NULL, 0, seed, 64);

	return dh_group_generate(p_bits, q_bits, hctx, seed, seed_size, NULL);
}

void dsa_group_delete(dsa_group *group)
{
	dh_group_delete(group);
}

dsa_key *dsa_key_generate(dsa_group *group, bignum_t *x)
{
	// Check bits
	if (dsa_valid_pq_lengths(CEIL_DIV(group->p->bits, 1024), CEIL_DIV(group->q->bits, 8)) == 0)
	{
		return NULL;
	}

	return dh_key_generate(group, x);
}

dsa_key *dsa_key_new(dsa_group *group, bignum_t *x, bignum_t *y)
{
	uint32_t p_bits = ROUND_UP(group->p->bits, 1024);
	uint32_t q_bits = ROUND_UP(group->q->bits, 8);

	if (dsa_valid_pq_lengths(p_bits, q_bits) == 0)
	{
		return NULL;
	}

	return dh_key_new(group, x, y);
}

void dsa_key_delete(dsa_key *key)
{
	return dh_key_delete(key);
}

dsa_signature *dsa_signature_new(dsa_key *key)
{
	uint32_t q_bits = ROUND_UP(key->group->q->bits, 8);
	dsa_signature *sign = malloc(sizeof(dsa_signature) + (2 * (q_bits / 8)));

	if (sign == NULL)
	{
		return NULL;
	}

	memset(sign, 0, sizeof(dsa_signature) + (2 * (q_bits / 8)));

	sign->r.bits = 0;
	sign->r.size = q_bits / 8;
	sign->r.sign = PTR_OFFSET(sign, sizeof(dsa_signature));

	sign->s.bits = 0;
	sign->s.size = q_bits / 8;
	sign->s.sign = PTR_OFFSET(sign, sizeof(dsa_signature) + (q_bits / 8));

	return sign;
}

void dsa_signature_delete(dsa_signature *sign)
{
	free(sign);
}

dsa_signature *dsa_sign(dsa_key *key, dsa_signature *dsign, void *salt, size_t salt_size, void *hash, size_t hash_size)
{
	bignum_t *k = NULL, *ik = NULL;
	bignum_t *z = NULL, *t = NULL;
	bignum_t *r = NULL, *s = NULL;

	size_t ctx_size = (5 * bignum_size(key->group->q->bits)) + bignum_size(key->group->p->bits);

	if (dsign->r.size < CEIL_DIV(key->group->q->bits, 8) || dsign->s.size < CEIL_DIV(key->group->q->bits, 8))
	{
		return NULL;
	}

	bignum_ctx_start(key->group->bctx, ctx_size);

	k = bignum_ctx_allocate_bignum(key->group->bctx, key->group->q->bits);
	ik = bignum_ctx_allocate_bignum(key->group->bctx, key->group->q->bits);
	r = bignum_ctx_allocate_bignum(key->group->bctx, key->group->q->bits);
	s = bignum_ctx_allocate_bignum(key->group->bctx, key->group->q->bits);
	z = bignum_ctx_allocate_bignum(key->group->bctx, MIN(key->group->q->bits, hash_size * 8));

	t = bignum_ctx_allocate_bignum(key->group->bctx, key->group->p->bits);

	// Finish hashing
	z = bignum_set_bytes_be(z, hash, MIN(key->group->q->bits / 8, hash_size));

	if (salt != NULL)
	{
		k = bignum_set_bytes_be(k, salt, salt_size);
	}
	else
	{
		k = bignum_rand_max(NULL, k, key->group->q);
	}

	ik = bignum_modinv(key->group->bctx, ik, k, key->group->q);

	// r = (g^k mod p) mod q.
	t = bignum_modexp(key->group->bctx, t, key->group->g, k, key->group->p);
	r = bignum_mod(key->group->bctx, r, t, key->group->q);

	// s = (ik(z + xr)) mod q.
	s = bignum_modmul(key->group->bctx, s, key->x, r, key->group->q);
	s = bignum_modadd(key->group->bctx, s, s, z, key->group->q);
	s = bignum_modmul(key->group->bctx, s, s, ik, key->group->q);

	// Load the signature
	bignum_get_bytes_be(r, dsign->r.sign, dsign->r.size);
	dsign->r.bits = r->bits;

	bignum_get_bytes_be(s, dsign->s.sign, dsign->s.size);
	dsign->s.bits = s->bits;

	bignum_ctx_end(key->group->bctx);

	return dsign;
}

uint32_t dsa_verify(dsa_key *key, dsa_signature *dsign, void *hash, size_t hash_size)
{
	uint32_t status = 0;
	size_t ctx_size = (6 * bignum_size(key->group->q->bits)) + (3 * bignum_size(key->group->p->bits));

	bignum_t *w = NULL;
	bignum_t *v = NULL;
	bignum_t *z = NULL;
	bignum_t *r = NULL, *s = NULL;

	bignum_t *u1 = NULL;
	bignum_t *u2 = NULL;
	bignum_t *u3 = NULL;
	bignum_t *u4 = NULL;

	bignum_ctx_start(key->group->bctx, ctx_size);

	w = bignum_ctx_allocate_bignum(key->group->bctx, key->group->q->bits);
	v = bignum_ctx_allocate_bignum(key->group->bctx, key->group->p->bits);
	r = bignum_ctx_allocate_bignum(key->group->bctx, key->group->q->bits);
	s = bignum_ctx_allocate_bignum(key->group->bctx, key->group->q->bits);
	z = bignum_ctx_allocate_bignum(key->group->bctx, MIN(key->group->q->bits, hash_size * 8));

	u1 = bignum_ctx_allocate_bignum(key->group->bctx, key->group->q->bits);
	u2 = bignum_ctx_allocate_bignum(key->group->bctx, key->group->q->bits);
	u3 = bignum_ctx_allocate_bignum(key->group->bctx, key->group->p->bits);
	u4 = bignum_ctx_allocate_bignum(key->group->bctx, key->group->p->bits);

	r = bignum_set_bytes_be(r, dsign->r.sign, dsign->r.size);
	s = bignum_set_bytes_be(s, dsign->s.sign, dsign->s.size);

	// Initial checks
	if (bignum_cmp(r, key->group->q) >= 0 || bignum_cmp(s, key->group->q) >= 0)
	{
		goto end;
	}

	// Hashing
	z = bignum_set_bytes_be(z, hash, MIN(key->group->q->bits / 8, hash_size));

	w = bignum_modinv(key->group->bctx, w, s, key->group->q);

	u1 = bignum_modmul(key->group->bctx, u1, z, w, key->group->q);
	u2 = bignum_modmul(key->group->bctx, u2, r, w, key->group->q);

	u3 = bignum_modexp(key->group->bctx, u3, key->group->g, u1, key->group->p);
	u4 = bignum_modexp(key->group->bctx, u4, key->y, u2, key->group->p);

	v = bignum_modmul(key->group->bctx, v, u3, u4, key->group->p);
	v = bignum_mod(key->group->bctx, v, v, key->group->q);

	if (bignum_cmp(v, r) == 0)
	{
		status = 1;
	}

end:
	bignum_ctx_end(key->group->bctx);
	return status;
}
