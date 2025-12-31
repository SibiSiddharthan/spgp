/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <dh.h>
#include <bignum.h>
#include <bignum-internal.h>
#include <drbg.h>

#include <stdlib.h>
#include <string.h>

#include "parameters/modp.h"
#include "parameters/ffdhe.h"

static uint32_t dh_group_bits(dh_safe_prime_id id)
{
	switch (id)
	{
	case DH_MODP_1024:
		return 1024;
	case DH_MODP_1536:
		return 1536;
	case DH_MODP_2048:
		return 2048;
	case DH_MODP_3072:
		return 3072;
	case DH_MODP_4096:
		return 4096;
	case DH_MODP_6144:
		return 6144;
	case DH_MODP_8192:
		return 8192;

	case DH_MODP_1024_160:
		return 1024;
	case DH_MODP_2048_224:
	case DH_MODP_2048_256:
		return 2048;

	case DH_FFDHE_2048:
		return 2048;
	case DH_FFDHE_3072:
		return 3072;
	case DH_FFDHE_4096:
		return 4096;
	case DH_FFDHE_6144:
		return 6144;
	case DH_FFDHE_8192:
		return 8192;
	default:
		return 0;
	}
}

dh_group *dh_group_custom_new(bignum_t *p, bignum_t *q, bignum_t *g)
{
	dh_group *group = NULL;
	uint32_t bits = p->bits;

	if (q->bits >= p->bits)
	{
		return NULL;
	}

	group = malloc(sizeof(dh_group));

	if (group == NULL)
	{
		return NULL;
	}

	memset(group, 0, sizeof(dh_group));

	group->id = 0;
	group->bctx = bignum_ctx_new(32 * bignum_size(bits));

	if (group->bctx == NULL)
	{
		free(group);
		return NULL;
	}

	group->p = p;
	group->q = q;
	group->g = g;

	return group;
}

dh_group *dh_group_new(dh_safe_prime_id id)
{
	dh_group *group = NULL;
	uint32_t bits = dh_group_bits(id);

	size_t offset = sizeof(dh_key);
	size_t required_size = sizeof(dh_key) + (3 * sizeof(bignum_t)); // p,q,g

	if (bits == 0)
	{
		return NULL;
	}

	group = malloc(required_size);

	if (group == NULL)
	{
		return NULL;
	}

	memset(group, 0, required_size);

	group->id = id;
	group->bctx = bignum_ctx_new(32 * bignum_size(bits));

	if (group->bctx == NULL)
	{
		free(group);
		return NULL;
	}

	// Initialize the bignum pointers
	group->p = PTR_OFFSET(group, offset);
	offset += sizeof(bignum_t);

	group->q = PTR_OFFSET(group, offset);
	offset += sizeof(bignum_t);

	group->g = PTR_OFFSET(group, offset);
	offset += sizeof(bignum_t);

	switch (id)
	{
	// MODP
	case DH_MODP_1024:
	{
		// p
		group->p->bits = 1024;
		group->p->size = 128;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_1024_p_words;

		// q
		group->q->bits = 1023;
		group->q->size = 128;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_1024_q_words;
	}
	break;
	case DH_MODP_1536:
	{
		// p
		group->p->bits = 1536;
		group->p->size = 192;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_1536_p_words;

		// q
		group->q->bits = 1535;
		group->q->size = 192;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_1536_q_words;
	}
	break;
	case DH_MODP_2048:
	{
		// p
		group->p->bits = 2048;
		group->p->size = 256;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_2048_p_words;

		// q
		group->q->bits = 2047;
		group->q->size = 256;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_2048_q_words;
	}
	break;
	case DH_MODP_3072:
	{
		// p
		group->p->bits = 3072;
		group->p->size = 384;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_3072_p_words;

		// q
		group->q->bits = 3071;
		group->q->size = 384;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_3072_q_words;
	}
	break;
	case DH_MODP_4096:
	{
		// p
		group->p->bits = 4096;
		group->p->size = 512;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_4096_p_words;

		// q
		group->q->bits = 4095;
		group->q->size = 512;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_4096_q_words;
	}
	break;
	case DH_MODP_6144:
	{
		// p
		group->p->bits = 6144;
		group->p->size = 768;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_6144_p_words;

		// q
		group->q->bits = 6143;
		group->q->size = 768;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_6144_q_words;
	}
	break;
	case DH_MODP_8192:
	{
		// p
		group->p->bits = 8192;
		group->p->size = 1024;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_8192_p_words;

		// q
		group->q->bits = 8191;
		group->q->size = 1024;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_8192_q_words;
	}
	break;

	// Small Subgroup
	case DH_MODP_1024_160:
	{
		// p
		group->p->bits = 1024;
		group->p->size = 128;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_1024_160_p_words;

		// q
		group->q->bits = 160;
		group->q->size = 24;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_1024_160_q_words;
	}
	break;
	case DH_MODP_2048_224:
	{
		// p
		group->p->bits = 2048;
		group->p->size = 256;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_2048_224_p_words;

		// q
		group->q->bits = 224;
		group->q->size = 32;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_2048_224_q_words;
	}
	break;
	case DH_MODP_2048_256:
	{
		// p
		group->p->bits = 2048;
		group->p->size = 256;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)modp_2048_256_p_words;

		// q
		group->q->bits = 256;
		group->q->size = 32;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)modp_2048_256_q_words;
	}
	break;

	// FFDHE
	case DH_FFDHE_2048:
	{
		// p
		group->p->bits = 2048;
		group->p->size = 256;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)ffdhe_2048_p_words;

		// q
		group->q->bits = 2047;
		group->q->size = 256;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)ffdhe_2048_q_words;
	}
	break;
	case DH_FFDHE_3072:
	{
		// p
		group->p->bits = 3072;
		group->p->size = 384;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)ffdhe_3072_p_words;

		// q
		group->q->bits = 3071;
		group->q->size = 384;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)ffdhe_3072_q_words;
	}
	break;
	case DH_FFDHE_4096:
	{
		// p
		group->p->bits = 4096;
		group->p->size = 512;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)ffdhe_4096_p_words;

		// q
		group->q->bits = 4095;
		group->q->size = 512;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)ffdhe_4096_q_words;
	}
	break;
	case DH_FFDHE_6144:
	{
		// p
		group->p->bits = 6144;
		group->p->size = 768;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)ffdhe_6144_p_words;

		// q
		group->q->bits = 6143;
		group->q->size = 768;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)ffdhe_6144_q_words;
	}
	break;
	case DH_FFDHE_8192:
	{
		// p
		group->p->bits = 8192;
		group->p->size = 1024;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)ffdhe_8192_p_words;

		// q
		group->q->bits = 8191;
		group->q->size = 1024;
		group->q->sign = 1;
		group->q->resize = 0;
		group->q->flags = 0;
		group->q->words = (bn_word_t *)ffdhe_8192_q_words;
	}
	break;
	}

	// g = 2
	bn_word_t g_words[] = {0x2};
	group->g->bits = 2;
	group->g->size = 8;
	group->g->sign = 1;
	group->g->resize = 0;
	group->g->flags = 0;
	group->g->words = g_words;

	return group;
}

void dh_group_delete(dh_group *group)
{
	if (group == NULL)
	{
		return;
	}

	bignum_ctx_delete(group->bctx);

	// Only free p,q,g if we generate a custom safe prime group
	if (group->id == 0)
	{
		bignum_delete(group->p);
		bignum_delete(group->q);
		bignum_delete(group->g);
	}

	free(group);
}

static bignum_t *dh_generate_candidate_q(hash_ctx *hctx, bignum_t *qc, void *seed, size_t seed_size, uint32_t q_bits)
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

static bignum_t *dh_generate_candidate_p(bignum_ctx *bctx, hash_ctx *hctx, bignum_t *pc, bignum_t *q, void *seed, size_t seed_size,
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

static bignum_t *dh_generate_candidate_g(bignum_ctx *bctx, hash_ctx *hctx, bignum_t *gc, bignum_t *p, bignum_t *q, void *seed,
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

dh_group *dh_group_generate(uint32_t p_bits, uint32_t q_bits, hash_ctx *hctx, void *seed, size_t seed_size, uint32_t *result)
{
	dh_group *group = NULL;

	bignum_t *qc = NULL, *pc = NULL, *gc = NULL;
	size_t ctx_size = 0;

	uint32_t counter = 0;
	uint32_t offset = 1;

	uint32_t l = 0;
	uint32_t s = 0;

	if (hctx == NULL || seed == NULL)
	{
		return NULL;
	}

	p_bits = ROUND_UP(p_bits, 8);
	q_bits = ROUND_UP(q_bits, 8);

	l = (p_bits / 8);
	s = CEIL_DIV(l, hctx->hash_size);

	// Check bits
	if (q_bits > p_bits)
	{
		return NULL;
	}

	if (CEIL_DIV(q_bits, 8) > hctx->hash_size)
	{
		return NULL;
	}

	if (CEIL_DIV(q_bits, 8) > seed_size)
	{
		return NULL;
	}

	group = malloc(sizeof(dh_group));

	if (group == NULL)
	{
		return NULL;
	}

	memset(group, 0, sizeof(dh_group));

	group->id = 0;
	group->bctx = bignum_ctx_new(32 * bignum_size(p_bits));

	if (group->bctx == NULL)
	{
		free(group);
		return NULL;
	}

	bignum_ctx_start(group->bctx, ctx_size);

	qc = bignum_ctx_allocate_bignum(group->bctx, q_bits);
	pc = bignum_ctx_allocate_bignum(group->bctx, p_bits);
	gc = bignum_ctx_allocate_bignum(group->bctx, p_bits);

	// Generate q
	do
	{
		qc = dh_generate_candidate_q(hctx, qc, seed, seed_size, q_bits);

		if (qc == NULL)
		{
			dh_group_delete(group);
			return NULL;
		}

	} while (bignum_is_probable_prime(group->bctx, qc) == 0);

	group->q = bignum_dup(NULL, qc);

	// Generate p
	for (uint32_t i = 0; i < (4 * l); ++i)
	{
		pc = dh_generate_candidate_p(group->bctx, hctx, pc, group->q, seed, seed_size, p_bits, q_bits, offset);

		if (pc == NULL)
		{
			dh_group_delete(group);
			return NULL;
		}

		if (bignum_get_bit(pc, p_bits - 1) == 0)
		{
			offset += s;
			continue;
		}

		if (bignum_is_probable_prime(group->bctx, pc))
		{
			counter = i;
			break;
		}

		offset += s;
	}

	group->p = bignum_dup(NULL, pc);

	// Generate g
	gc = dh_generate_candidate_g(group->bctx, hctx, gc, group->p, group->q, seed, seed_size, p_bits);

	if (gc == NULL)
	{
		dh_group_delete(group);
		return NULL;
	}

	group->g = bignum_dup(NULL, gc);

	bignum_ctx_end(group->bctx);

	if (result != NULL)
	{
		*result = counter;
	}

	return group;
}

uint32_t dh_group_validate(dh_group *group, uint32_t counter, hash_ctx *hctx, void *seed, size_t seed_size)
{
	bignum_t *qc = NULL, *pc = NULL, *gc = NULL;
	size_t ctx_size = 0;

	uint32_t p_bits = group->p->bits;
	uint32_t q_bits = group->q->bits;

	uint32_t offset = 1;

	uint32_t l = (p_bits / 8);
	uint32_t s = CEIL_DIV(l, hctx->hash_size);

	// Check bits
	if (CEIL_DIV(q_bits, 8) > hctx->hash_size)
	{
		return 0;
	}

	if (CEIL_DIV(q_bits, 8) > seed_size)
	{
		return 0;
	}

	if (counter >= (4 * l))
	{
		return 0;
	}

	ctx_size = bignum_size(q_bits) + (2 * bignum_size(p_bits));

	bignum_ctx_start(group->bctx, ctx_size);

	qc = bignum_ctx_allocate_bignum(group->bctx, q_bits);
	pc = bignum_ctx_allocate_bignum(group->bctx, p_bits);
	gc = bignum_ctx_allocate_bignum(group->bctx, p_bits);

	// Check q
	qc = dh_generate_candidate_q(hctx, qc, seed, seed_size, q_bits);

	if (qc == NULL)
	{
		return 0;
	}

	if (bignum_cmp(group->q, qc) != 0)
	{
		return 0;
	}

	// Check prime
	if (bignum_is_probable_prime(group->bctx, qc) == 0)
	{
		return 0;
	}

	// Check p
	for (uint32_t i = 0; i < (4 * l); ++i)
	{
		pc = dh_generate_candidate_p(group->bctx, hctx, pc, group->q, seed, seed_size, p_bits, q_bits, offset);

		if (pc == NULL)
		{
			return 0;
		}

		if (bignum_get_bit(pc, p_bits - 1) == 0)
		{
			offset += s;
			continue;
		}

		if (bignum_is_probable_prime(group->bctx, pc))
		{
			if (i != counter)
			{
				return 0;
			}

			if (bignum_cmp(group->p, pc) != 0)
			{
				return 0;
			}
		}

		offset += s;
	}

	// Check g
	gc = dh_generate_candidate_g(group->bctx, hctx, gc, group->p, group->q, seed, seed_size, p_bits);

	if (gc == NULL)
	{
		return 0;
	}

	if (bignum_cmp(group->g, gc) != 0)
	{
		return 0;
	}

	bignum_ctx_end(group->bctx);

	return 1;
}

dh_key *dh_key_generate(dh_group *group, bignum_t *x)
{
	dh_key *key = NULL;

	key = malloc(sizeof(dh_key));

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, sizeof(dh_key));

	if (x == NULL)
	{
		x = bignum_rand_max(NULL, x, group->q);

		if (x == NULL)
		{
			free(key);
			return NULL;
		}
	}
	else
	{
		if (bignum_cmp_abs(x, group->q) >= 0)
		{
			free(key);
			return NULL;
		}
	}

	// Set the group
	key->group = group;

	// Set the private key
	key->x = x;

	// Calculate the public key
	key->y = bignum_modexp(group->bctx, NULL, group->g, key->x, group->p);

	return key;
}

uint32_t dh_key_validate(dh_key *key, uint32_t full)
{
	uint32_t status = 0;

	bignum_t *pm2 = NULL;
	bignum_t *r = NULL;

	// y < 2
	if (key->y->bits < 2)
	{
		goto end;
	}

	// y > p-2
	pm2 = bignum_dup(NULL, key->group->p);
	pm2 = bignum_usub_word(pm2, key->group->p, 2);

	if (bignum_cmp_abs(key->y, pm2) > 0)
	{
		goto end;
	}

	bignum_delete(pm2);

	// (y^q)modp != 1
	if (full)
	{
		r = bignum_modexp(key->group->bctx, NULL, key->y, key->group->q, key->group->p);

		if (r->bits != 1)
		{
			goto end;
		}
	}

	status = 1;

end:
	bignum_delete(pm2);
	bignum_delete(r);

	return status;
}

dh_key *dh_key_new(dh_group *group, bignum_t *x, bignum_t *y)
{
	dh_key *key = NULL;

	key = malloc(sizeof(dh_key));

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, sizeof(dh_key));

	key->group = group;
	key->x = x;
	key->y = y;

	return key;
}

void dh_key_delete(dh_key *key)
{
	if (key == NULL)
	{
		return;
	}

	dh_group_delete(key->group);
	bignum_delete(key->x);
	bignum_delete(key->y);
	free(key);
}
