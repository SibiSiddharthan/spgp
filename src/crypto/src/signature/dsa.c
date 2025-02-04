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

static bignum_t *dsa_generate_candidate_q(hash_ctx *hctx, bignum_t *qc, void *seed, size_t seed_size, uint32_t q_bits)
{
	drbg_ctx *drbg = get_default_drbg();

	uint32_t hash_size = 0;
	uint32_t hash_offset = 0;

	uint32_t n = (q_bits / 8);

	byte_t hash[MAX_HASH_SIZE] = {0};

	if (drbg == NULL)
	{
		return NULL;
	}

	drbg_generate(drbg, 0, NULL, 0, seed, seed_size);

	hash_reset(hctx);
	hash_update(hctx, seed, seed_size);
	hash_final(hctx, hash, MAX_HASH_SIZE);

	// Truncate to q_bits
	hash_size = MIN(hctx->hash_size, n);
	hash_offset = hctx->hash_size - hash_size;

	// Set the first and last bits to 1.
	bignum_set_bytes_be(qc, PTR_OFFSET(hash, hash_offset), hash_size);
	bignum_set_bit(qc, 0);
	bignum_set_bit(qc, q_bits - 1);

	return qc;
}

static bignum_t *dsa_generate_candidate_p(bignum_ctx *bctx, hash_ctx *hctx, bignum_t *pc, bignum_t *q, void *seed, size_t seed_size,
										  uint32_t p_bits, uint32_t q_bits, uint32_t offset)
{
	bignum_t *q2 = NULL, *ds = NULL, *c = NULL;

	uint32_t hash_size = 0;
	uint32_t hash_offset = 0;

	uint32_t l = (p_bits / 8);
	uint32_t s = CEIL_DIV(l, hctx->hash_size);

	uint32_t start = l;
	uint32_t remaining = l;

	void *pseed = NULL;
	void *pbuffer = NULL;

	byte_t hash[MAX_HASH_SIZE] = {0};

	bignum_ctx_start(bctx, (2 * bignum_size(q_bits + 1)) + bignum_size((seed_size + 1) * 8) + seed_size + l);

	q2 = bignum_ctx_allocate_bignum(bctx, q_bits + 1);
	ds = bignum_ctx_allocate_bignum(bctx, (seed_size + 1) * 8);
	c = bignum_ctx_allocate_bignum(bctx, q_bits + 1);

	pseed = bignum_ctx_allocate_raw(bctx, seed_size);
	pbuffer = bignum_ctx_allocate_raw(bctx, l);

	ds = bignum_set_bytes_be(ds, seed, seed_size);
	ds = bignum_uadd_word(ds, ds, offset);

	for (uint32_t j = 0; j < s; ++j)
	{
		ds = bignum_uadd_word(ds, ds, j);
		ds = bignum_umod2p(ds, seed_size * 8);

		bignum_get_bytes_be(ds, pseed, seed_size);

		hash_reset(hctx);
		hash_update(hctx, seed, seed_size);
		hash_final(hctx, hash, MAX_HASH_SIZE);

		hash_size = MIN(hctx->hash_size, remaining);
		hash_offset = hctx->hash_size - hash_size;
		start -= hash_size;

		memcpy(PTR_OFFSET(pbuffer, start), PTR_OFFSET(hash, hash_offset), hash_size);
	}

	bignum_set_bytes_be(pc, pbuffer, l);
	bignum_set_bit(pc, p_bits - 1);

	q2 = bignum_lshift1(q2, q);
	c = bignum_mod(bctx, c, pc, q2);
	pc = bignum_sub(pc, pc, c);
	pc = bignum_uadd_word(pc, pc, 1);

	bignum_ctx_end(bctx);

	return pc;
}

static bignum_t *dsa_generate_candidate_g(bignum_ctx *bctx, hash_ctx *hctx, bignum_t *gc, bignum_t *p, bignum_t *q, void *seed,
										  size_t seed_size, uint32_t p_bits)
{
	bignum_t *e = NULL, *w = NULL;

	uint32_t l = (p_bits / 8);

	uint16_t count_be = 0;
	uint8_t index = 1;

	byte_t hash[MAX_HASH_SIZE] = {0};

	bignum_ctx_start(bctx, bignum_size(p_bits) + bignum_size(hctx->hash_size * 8));

	e = bignum_ctx_allocate_bignum(bctx, p_bits);
	w = bignum_ctx_allocate_bignum(bctx, hctx->hash_size * 8);

	e = bignum_usub_word(e, p, 1);
	e = bignum_div(bctx, e, e, q);

	for (uint16_t c = 1; c < (4 * l); ++c)
	{
		count_be = BSWAP_16(c);

		hash_reset(hctx);
		hash_update(hctx, seed, seed_size);
		hash_update(hctx, "ggen", 4);
		hash_update(hctx, &index, 1);
		hash_update(hctx, &count_be, 2);
		hash_final(hctx, hash, MAX_HASH_SIZE);

		w = bignum_set_bytes_be(w, hash, hctx->hash_size);
		gc = bignum_modexp(bctx, gc, w, e, p);

		if (gc->bits >= 2)
		{
			break;
		}

		if (c == ((4 * l) - 1))
		{
			gc = NULL;
		}
	}

	bignum_ctx_end(bctx);

	return gc;
}

uint32_t dsa_parameters_generate(hash_ctx *hctx, bignum_t *p, bignum_t *q, bignum_t *g, uint32_t p_bits, uint32_t q_bits, void *seed,
								 size_t seed_size)
{

	drbg_ctx *drbg = NULL;
	bignum_ctx *bctx = NULL;

	bignum_t *qc = NULL, *pc = NULL, *gc = NULL;
	size_t ctx_size = 0;

	uint32_t counter = (uint32_t)-1;
	uint32_t offset = 1;

	uint32_t l = (p_bits / 8);
	uint32_t s = CEIL_DIV(l, hctx->hash_size);

	// Check bits
	if (dsa_valid_pq_lengths(p_bits, q_bits) == 0)
	{
		return (uint32_t)-1;
	}

	if (CEIL_DIV(q->bits, 8) > hctx->hash_size)
	{
		return (uint32_t)-1;
	}

	if (CEIL_DIV(q->bits, 8) > seed_size)
	{
		return (uint32_t)-1;
	}

	drbg = get_default_drbg();

	if (drbg == NULL)
	{
		return (uint32_t)-1;
	}

	ctx_size = bignum_size(q_bits) + (2 * bignum_size(p_bits));
	bctx = bignum_ctx_new(256 + ctx_size);

	if (bctx == NULL)
	{
		return (uint32_t)-1;
	}

	bignum_ctx_start(bctx, ctx_size);

	qc = bignum_ctx_allocate_bignum(bctx, q_bits);
	pc = bignum_ctx_allocate_bignum(bctx, p_bits);
	gc = bignum_ctx_allocate_bignum(bctx, p_bits);

	// Generate q
	do
	{
		qc = dsa_generate_candidate_q(hctx, qc, seed, seed_size, q_bits);

		if (qc == NULL)
		{
			return (uint32_t)-1;
		}

	} while (bignum_is_probable_prime(bctx, qc) == 0);

	bignum_copy(q, qc);

	// Generate p
	for (uint32_t i = 0; i < (4 * l); ++i)
	{
		pc = dsa_generate_candidate_p(bctx, hctx, pc, q, seed, seed_size, p_bits, q_bits, offset);

		if (pc == NULL)
		{
			return (uint32_t)-1;
		}

		if (bignum_get_bit(pc, p_bits - 1) == 0)
		{
			offset += s;
			continue;
		}

		if (bignum_is_probable_prime(bctx, pc))
		{
			counter = i;
			break;
		}

		offset += s;
	}

	bignum_copy(p, pc);

	// Generate g
	gc = dsa_generate_candidate_g(bctx, hctx, gc, p, q, seed, seed_size, p_bits);

	if (gc == NULL)
	{
		return (uint32_t)-1;
	}

	bignum_copy(g, gc);

	bignum_ctx_end(bctx);
	bignum_ctx_delete(bctx);

	return counter;
}

uint32_t dsa_parameters_validate(hash_ctx *hctx, bignum_t *p, bignum_t *q, bignum_t *g, uint32_t counter, void *seed, size_t seed_size)
{
	bignum_ctx *bctx = NULL;

	bignum_t *qc = NULL, *pc = NULL, *gc = NULL;
	size_t ctx_size = 0;

	uint32_t p_bits = p->bits;
	uint32_t q_bits = q->bits;

	uint32_t offset = 1;

	uint32_t l = (p_bits / 8);
	uint32_t s = CEIL_DIV(l, hctx->hash_size);

	// Check bits
	if (dsa_valid_pq_lengths(p_bits, q_bits) == 0)
	{
		return 0;
	}

	if (CEIL_DIV(q->bits, 8) > hctx->hash_size)
	{
		return 0;
	}

	if (CEIL_DIV(q->bits, 8) > seed_size)
	{
		return 0;
	}

	if (counter >= (4 * l))
	{
		return 0;
	}

	ctx_size = bignum_size(q_bits) + (2 * bignum_size(p_bits));
	bctx = bignum_ctx_new(256 + ctx_size);

	if (bctx == NULL)
	{
		return 0;
	}

	bignum_ctx_start(bctx, ctx_size);

	qc = bignum_ctx_allocate_bignum(bctx, q_bits);
	pc = bignum_ctx_allocate_bignum(bctx, p_bits);
	gc = bignum_ctx_allocate_bignum(bctx, p_bits);

	// Check q
	qc = dsa_generate_candidate_q(hctx, qc, seed, seed_size, q_bits);

	if (qc == NULL)
	{
		return 0;
	}

	if (bignum_cmp(q, qc) != 0)
	{
		return 0;
	}

	// Check prime
	if (bignum_is_probable_prime(bctx, qc) == 0)
	{
		return 0;
	}

	// Check p
	for (uint32_t i = 0; i < (4 * l); ++i)
	{
		pc = dsa_generate_candidate_p(bctx, hctx, pc, q, seed, seed_size, p_bits, q_bits, offset);

		if (pc == NULL)
		{
			return 0;
		}

		if (bignum_get_bit(pc, p_bits - 1) == 0)
		{
			offset += s;
			continue;
		}

		if (bignum_is_probable_prime(bctx, pc))
		{
			if (i != counter)
			{
				return 0;
			}

			if (bignum_cmp(p, pc) != 0)
			{
				return 0;
			}
		}

		offset += s;
	}

	// Check g
	gc = dsa_generate_candidate_g(bctx, hctx, gc, p, q, seed, seed_size, p_bits);

	if (gc == NULL)
	{
		return (uint32_t)-1;
	}

	if (bignum_cmp(g, gc) != 0)
	{
		return 0;
	}

	bignum_ctx_end(bctx);
	bignum_ctx_delete(bctx);

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
	uint32_t required_size = 0;
	uint32_t bctx_size = 0;
	uint32_t bignums_size = 0;

	p_bits = ROUND_UP(p_bits, 1024);
	q_bits = ROUND_UP(q_bits, 8);

	if (dsa_valid_pq_lengths(p_bits, q_bits) == 0)
	{
		return NULL;
	}

	bctx_size += 16 * (p_bits * 2) / 8; // For bctx

	bignums_size = bignum_size(p_bits) + bignum_size(q_bits)   // p, q
				   + bignum_size(p_bits)                       // g
				   + bignum_size(q_bits) + bignum_size(p_bits) // x,y
				   + bignum_size(p_bits)                       // mu
		;

	required_size = sizeof(dsa_key) + bctx_size + bignums_size;

	key = malloc(required_size);

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, required_size);

	key->size = required_size;
	key->p_bits = p_bits;
	key->q_bits = q_bits;

	key->bctx = bignum_ctx_init(PTR_OFFSET(key, sizeof(dsa_key) + bignums_size), bctx_size);

	return key;
}

void dsa_key_delete(dsa_key *key)
{
	memset(key, 0, key->size);
	free(key);
}

dsa_key *dsa_key_set_pqg(dsa_key *key, bignum_t *p, bignum_t *q, bignum_t *g)
{
	uint32_t p_offset = sizeof(dsa_key);
	uint32_t q_offset = p_offset + bignum_size(p->bits);
	uint32_t g_offset = q_offset + bignum_size(q->bits);

	key->p = bignum_init(PTR_OFFSET(key, p_offset), bignum_size(key->p_bits), p->bits);
	key->q = bignum_init(PTR_OFFSET(key, q_offset), bignum_size(key->q_bits), q->bits);
	key->g = bignum_init(PTR_OFFSET(key, g_offset), bignum_size(key->p_bits), g->bits);

	if (key->p == NULL || key->q == NULL || key->g == NULL)
	{
		return NULL;
	}

	bignum_copy(key->p, p);
	bignum_copy(key->q, q);
	bignum_copy(key->g, g);

	return key;
}

dsa_key *dsa_key_set_xy(dsa_key *key, bignum_t *x, bignum_t *y)
{
	uint32_t x_offset = sizeof(dsa_key) + (2 * bignum_size(key->p_bits) + bignum_size(key->q_bits));
	uint32_t y_offset = x_offset + bignum_size(x->bits);

	key->x = bignum_init(PTR_OFFSET(key, x_offset), bignum_size(key->q_bits), x->bits);
	key->y = bignum_init(PTR_OFFSET(key, y_offset), bignum_size(key->p_bits), y->bits);

	if (key->x == NULL || key->y == NULL)
	{
		return NULL;
	}

	bignum_copy(key->x, x);
	bignum_copy(key->y, y);

	return key;
}

dsa_ctx *dsa_sign_new(dsa_key *key, hash_ctx *hctx, void *salt, size_t salt_size)
{
	dsa_ctx *dctx = NULL;

	if (salt != NULL && salt_size > (key->q_bits / 8))
	{
		return NULL;
	}

	dctx = (dsa_ctx *)malloc(sizeof(dsa_ctx));

	if (dctx == NULL)
	{
		return NULL;
	}

	dctx->key = key;
	dctx->hctx = hctx;
	dctx->salt = salt;
	dctx->salt_size = salt_size;

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

dsa_signature *dsa_sign_final(dsa_ctx *dctx, void *signature, size_t size)
{
	dsa_signature *dsign = signature;

	dsa_key *key = dctx->key;
	hash_ctx *hctx = dctx->hctx;
	bignum_ctx *bctx = dctx->key->bctx;

	size_t hash_size = hctx->hash_size;
	size_t ctx_size = (3 * bignum_size(key->q->bits)) + bignum_size(key->p->bits);
	size_t signature_size = sizeof(dsa_signature) + (2 * bignum_size(key->q->bits));

	bignum_t *k = NULL;
	bignum_t *ik = NULL;
	bignum_t *z = NULL;
	bignum_t *t = NULL;

	// Allocate the signature
	if (dsign == NULL)
	{
		dsign = malloc(signature_size);
	}
	else
	{
		if (size < signature_size)
		{
			return NULL;
		}
	}

	if (dsign == NULL)
	{
		return NULL;
	}

	dsign->r = PTR_OFFSET(dsign, sizeof(dsa_signature));
	dsign->s = PTR_OFFSET(dsign, sizeof(dsa_signature) + bignum_size(key->q->bits));

	dsign->r = bignum_init(dsign->r, bignum_size(key->q->bits), key->q->bits);
	dsign->s = bignum_init(dsign->s, bignum_size(key->q->bits), key->q->bits);

	bignum_ctx_start(bctx, ctx_size);

	k = bignum_ctx_allocate_bignum(bctx, key->q->bits);
	ik = bignum_ctx_allocate_bignum(bctx, key->q->bits);
	z = bignum_ctx_allocate_bignum(bctx, MIN(key->q->bits, hash_size * 8));

	t = bignum_ctx_allocate_bignum(bctx, key->p->bits);

	// Finish hashing
	hash_final(dctx->hctx, NULL, hash_size);
	z = bignum_set_bytes_be(z, dctx->hctx->hash, MIN(key->q->bits / 8, hash_size));

	if (dctx->salt != NULL)
	{
		k = bignum_set_bytes_be(k, dctx->salt, dctx->salt_size);
	}
	else
	{
		k = bignum_rand_max(NULL, k, key->q);
	}

	ik = bignum_modinv(bctx, ik, k, key->q);

	// r = (g^k mod p) mod q.
	t = bignum_modexp(bctx, t, key->g, k, key->p);
	dsign->r = bignum_mod(bctx, dsign->r, t, key->q);

	// s = (ik(z + xr)) mod q.
	dsign->s = bignum_modmul(bctx, dsign->s, key->x, dsign->r, key->q);
	dsign->s = bignum_modadd(bctx, dsign->s, dsign->s, z, key->q);
	dsign->s = bignum_modmul(bctx, dsign->s, dsign->s, ik, key->q);

	bignum_ctx_end(bctx);

	return dsign;
}

dsa_signature *dsa_sign(dsa_key *key, hash_ctx *hctx, void *salt, size_t salt_size, void *message, size_t message_size, void *signature,
						size_t signature_size)
{
	dsa_ctx *dctx = dsa_sign_new(key, hctx, salt, salt_size);
	dsa_signature *dsign = NULL;

	if (dctx == NULL)
	{
		return NULL;
	}

	dsa_sign_update(dctx, message, message_size);
	dsign = dsa_sign_final(dctx, signature, signature_size);

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

uint32_t dsa_verify_final(dsa_ctx *dctx, dsa_signature *dsign)
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
		return 0;
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
	z = bignum_set_bytes_be(z, dctx->hctx->hash, MIN(key->q->bits / 8, hash_size));

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
		return 1;
	}

	return 0;
}

uint32_t dsa_verify(dsa_key *key, hash_ctx *hctx, void *message, size_t size, dsa_signature *dsign)
{
	uint32_t status = 0;
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
