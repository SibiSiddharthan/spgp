/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <dh.h>
#include <bignum.h>
#include <bignum-internal.h>

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
}
