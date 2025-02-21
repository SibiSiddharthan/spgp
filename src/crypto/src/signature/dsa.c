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

dsa_signature *dsa_sign(dsa_key *key, void *salt, size_t salt_size, void *hash, size_t hash_size, void *signature, size_t signature_size)
{
	dsa_signature *dsign = signature;

	size_t ctx_size = (5 * bignum_size(key->q->bits)) + bignum_size(key->p->bits);
	size_t required_signature_size = sizeof(dsa_signature) + (2 * CEIL_DIV(key->q->bits, 8));

	bignum_t *k = NULL, *ik = NULL;
	bignum_t *z = NULL, *t = NULL;
	bignum_t *r = NULL, *s = NULL;

	// Allocate the signature
	if (dsign == NULL)
	{
		dsign = malloc(required_signature_size);
	}
	else
	{
		if (signature_size < required_signature_size)
		{
			return NULL;
		}
	}

	if (dsign == NULL)
	{
		return NULL;
	}

	dsign->r.size = CEIL_DIV(key->q->bits, 8);
	dsign->s.size = CEIL_DIV(key->q->bits, 8);

	dsign->r.sign = PTR_OFFSET(dsign, sizeof(dsa_signature));
	dsign->s.sign = PTR_OFFSET(dsign, sizeof(dsa_signature) + dsign->r.size);

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

	dsign->r.size = bignum_get_bytes_be(r, dsign->r.sign, dsign->r.size);
	dsign->r.bits = r->bits;

	dsign->s.size = bignum_get_bytes_be(s, dsign->s.sign, dsign->s.size);
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
