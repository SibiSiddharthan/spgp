/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <ec.h>
#include <bignum.h>
#include <bignum-internal.h>

#include <stdlib.h>
#include <string.h>

#include "curves/prime.h"
#include "curves/binary.h"
#include "curves/brainpool.h"
#include "curves/montgomery.h"
#include "curves/edwards.h"

uint32_t ec_group_bits(curve_id id)
{
	switch (id)
	{
	case EC_CUSTOM:
		return 0;

	// NIST
	// Prime curves
	case EC_NIST_P192:
		return 192;
	case EC_NIST_P224:
		return 224;
	case EC_NIST_P256:
		return 256;
	case EC_NIST_P384:
		return 384;
	case EC_NIST_P521:
		return 521;

	// Binary curves
	case EC_NIST_K163:
	case EC_NIST_B163:
		return 163;
	case EC_NIST_K233:
	case EC_NIST_B233:
		return 233;
	case EC_NIST_K283:
	case EC_NIST_B283:
		return 283;
	case EC_NIST_K409:
	case EC_NIST_B409:
		return 409;
	case EC_NIST_K571:
	case EC_NIST_B571:
		return 571;

	// SEC
	// Prime curves
	case EC_SECP_160K1:
	case EC_SECP_160R1:
	case EC_SECP_160R2:
		return 160;
	case EC_SECP_192K1:
	case EC_SECP_192R1:
		return 192;
	case EC_SECP_224K1:
	case EC_SECP_224R1:
		return 224;
	case EC_SECP_256K1:
	case EC_SECP_256R1:
		return 256;
	case EC_SECP_384R1:
		return 384;
	case EC_SECP_521R1:
		return 521;

	// Binary curves
	case EC_SECT_163K1:
	case EC_SECT_163R1:
	case EC_SECT_163R2:
		return 163;
	case EC_SECT_193R1:
	case EC_SECT_193R2:
		return 193;
	case EC_SECT_233K1:
	case EC_SECT_233R1:
		return 233;
	case EC_SECT_239K1:
		return 239;
	case EC_SECT_283K1:
	case EC_SECT_283R1:
		return 283;
	case EC_SECT_409K1:
	case EC_SECT_409R1:
		return 409;
	case EC_SECT_571K1:
	case EC_SECT_571R1:
		return 571;

	// Brainpool
	case EC_BRAINPOOL_160R1:
	case EC_BRAINPOOL_160T1:
		return 160;
	case EC_BRAINPOOL_192R1:
	case EC_BRAINPOOL_192T1:
		return 192;
	case EC_BRAINPOOL_224R1:
	case EC_BRAINPOOL_224T1:
		return 224;
	case EC_BRAINPOOL_256R1:
	case EC_BRAINPOOL_256T1:
		return 256;
	case EC_BRAINPOOL_320R1:
	case EC_BRAINPOOL_320T1:
		return 320;
	case EC_BRAINPOOL_384R1:
	case EC_BRAINPOOL_384T1:
		return 384;
	case EC_BRAINPOOL_512R1:
	case EC_BRAINPOOL_512T1:
		return 512;

	// Montgomery
	case EC_CURVE25519:
		return 255;
	case EC_CURVE448:
		return 448;

	// Twisted Edwards
	case EC_ED25519:
		return 255;
	case EC_ED448:
		return 448;

	default:
		return 0;
	}
}

ec_group *ec_group_new(curve_id id)
{
	ec_group *group = NULL;
	uint32_t bits = ec_group_bits(id);

	// For prime and order p,n
	// For base point gx,gy
	// For curve parameters a,b
	size_t ec_group_size = sizeof(ec_group) + (4 * sizeof(bignum_t *)) + (6 * sizeof(bignum_t));

	if (bits == 0)
	{
		return NULL;
	}

	group = malloc(ec_group_size);

	if (group == NULL)
	{
		return NULL;
	}

	memset(group, 0, ec_group_size);

	group->id = id;
	group->bits = bits;
	group->bctx = bignum_ctx_new(32 * bignum_size(bits));

	if (group->bctx == NULL)
	{
		free(group);
		return NULL;
	}

	size_t offset = sizeof(ec_group);

	// Store the pointers first
	group->g = PTR_OFFSET(group, offset);
	offset += sizeof(ec_point);

	group->parameters = PTR_OFFSET(group, offset);
	offset += 2 * sizeof(bignum_t *); // All parameters consist of 2 bignums only

	// Assign the memory region for the pointers
	group->p = PTR_OFFSET(group, offset);
	offset += sizeof(bignum_t);

	group->n = PTR_OFFSET(group, offset);
	offset += sizeof(bignum_t);

	group->g->x = PTR_OFFSET(group, offset);
	offset += sizeof(bignum_t);

	group->g->y = PTR_OFFSET(group, offset);
	offset += sizeof(bignum_t);

	group->parameters->a = PTR_OFFSET(group, offset);
	offset += sizeof(bignum_t);

	group->parameters->b = PTR_OFFSET(group, offset);
	offset += sizeof(bignum_t);

	switch (id)
	{
	// NIST
	// Prime curves
	case EC_NIST_P192:
	{
	ec_nist_p192:
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 192;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_p192_p_words;

		// n
		group->n->bits = 192;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_p192_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 192;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)nist_p192_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 191;
		group->prime_parameters->b->size = 24;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)nist_p192_b_words;

		// g->x
		group->g->x->bits = 189;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_p192_gx_words;

		// g->y
		group->g->y->bits = 187;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_p192_gy_words;

		goto prime_init;
	}
	break;
	case EC_NIST_P224:
	{
	ec_nist_p224:
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 224;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_p224_p_words;

		// n
		group->n->bits = 224;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_p224_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 224;
		group->prime_parameters->a->size = 32;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)nist_p224_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 224;
		group->prime_parameters->b->size = 32;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)nist_p224_b_words;

		// g->x
		group->g->x->bits = 224;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_p224_gx_words;

		// g->y
		group->g->y->bits = 224;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_p224_gy_words;

		goto prime_init;
	}
	break;
	case EC_NIST_P256:
	{
	ec_nist_p256:
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 256;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_p256_p_words;

		// n
		group->n->bits = 256;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_p256_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 256;
		group->prime_parameters->a->size = 32;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)nist_p256_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 255;
		group->prime_parameters->b->size = 32;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)nist_p256_b_words;

		// g->x
		group->g->x->bits = 255;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_p256_gx_words;

		// g->y
		group->g->y->bits = 255;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_p256_gy_words;

		goto prime_init;
	}
	break;
	case EC_NIST_P384:
	{
	ec_nist_p384:
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 384;
		group->p->size = 48;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_p384_p_words;

		// n
		group->n->bits = 384;
		group->n->size = 48;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_p384_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 384;
		group->prime_parameters->a->size = 48;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)nist_p384_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 384;
		group->prime_parameters->b->size = 48;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)nist_p384_b_words;

		// g->x
		group->g->x->bits = 384;
		group->g->x->size = 48;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_p384_gx_words;

		// g->y
		group->g->y->bits = 382;
		group->g->y->size = 48;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_p384_gy_words;

		goto prime_init;
	}
	break;
	case EC_NIST_P521:
	{
	ec_nist_p521:
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 521;
		group->p->size = 72;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_p521_p_words;

		// n
		group->n->bits = 521;
		group->n->size = 72;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_p521_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 521;
		group->prime_parameters->a->size = 72;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)nist_p521_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 519;
		group->prime_parameters->b->size = 72;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)nist_p521_b_words;

		// g->x
		group->g->x->bits = 520;
		group->g->x->size = 72;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_p521_gx_words;

		// g->y
		group->g->y->bits = 521;
		group->g->y->size = 72;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_p521_gy_words;

		goto prime_init;
	}
	break;

	// Binary curves (Koblitz)
	case EC_NIST_K163:
	{
	ec_nist_k163:
		// cofactor (h)
		group->cofactor = 2;

		// p
		group->p->bits = 164;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k163_p_words;

		// n
		group->n->bits = 163;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k163_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k163_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 1;
		group->binary_parameters->b->size = 8;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_k163_b_words;

		// g->x
		group->g->x->bits = 162;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_k163_gx_words;

		// g->y
		group->g->y->bits = 162;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_k163_gy_words;

		goto binary_init;
	}
	break;
	case EC_NIST_K233:
	{
	ec_nist_k233:
		// cofactor (h)
		group->cofactor = 4;

		// p
		group->p->bits = 234;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k233_p_words;

		// n
		group->n->bits = 232;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k233_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k233_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 1;
		group->binary_parameters->b->size = 8;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_k233_b_words;

		// g->x
		group->g->x->bits = 233;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_k233_gx_words;

		// g->y
		group->g->y->bits = 233;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_k233_gy_words;

		goto binary_init;
	}
	break;
	case EC_NIST_K283:
	{
	ec_nist_k283:
		// cofactor (h)
		group->cofactor = 4;

		// p
		group->p->bits = 284;
		group->p->size = 40;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k283_p_words;

		// n
		group->n->bits = 281;
		group->n->size = 40;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k283_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k283_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 1;
		group->binary_parameters->b->size = 8;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_k283_b_words;

		// g->x
		group->g->x->bits = 283;
		group->g->x->size = 40;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_k283_gx_words;

		// g->y
		group->g->y->bits = 281;
		group->g->y->size = 40;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_k283_gy_words;

		goto binary_init;
	}
	break;
	case EC_NIST_K409:
	{
	ec_nist_k409:
		// cofactor (h)
		group->cofactor = 4;

		// p
		group->p->bits = 410;
		group->p->size = 56;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k409_p_words;

		// n
		group->n->bits = 407;
		group->n->size = 56;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k409_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k409_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 1;
		group->binary_parameters->b->size = 8;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_k409_b_words;

		// g->x
		group->g->x->bits = 407;
		group->g->x->size = 56;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_k409_gx_words;

		// g->y
		group->g->y->bits = 409;
		group->g->y->size = 56;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_k409_gy_words;

		goto binary_init;
	}
	break;
	case EC_NIST_K571:
	{
	ec_nist_k571:
		// cofactor (h)
		group->cofactor = 4;

		// p
		group->p->bits = 572;
		group->p->size = 72;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k571_p_words;

		// n
		group->n->bits = 570;
		group->n->size = 72;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k571_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k571_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 1;
		group->binary_parameters->b->size = 8;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_k571_b_words;

		// g->x
		group->g->x->bits = 570;
		group->g->x->size = 72;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_k571_gx_words;

		// g->y
		group->g->y->bits = 570;
		group->g->y->size = 72;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_k571_gy_words;

		goto binary_init;
	}
	break;

	// Binary curves (Psuedo random)
	case EC_NIST_B163:
	{
	ec_nist_b163:
		// cofactor (h)
		group->cofactor = 2;

		// p
		group->p->bits = 164;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b163_p_words;

		// n
		group->n->bits = 163;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b163_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b163_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 162;
		group->binary_parameters->b->size = 24;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_b163_b_words;

		// g->x
		group->g->x->bits = 162;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_b163_gx_words;

		// g->y
		group->g->y->bits = 160;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_b163_gy_words;

		goto binary_init;
	}
	break;
	case EC_NIST_B233:
	{
	ec_nist_b233:
		// cofactor (h)
		group->cofactor = 2;

		// p
		group->p->bits = 234;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b233_p_words;

		// n
		group->n->bits = 233;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b233_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b233_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 231;
		group->binary_parameters->b->size = 32;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_b233_b_words;

		// g->x
		group->g->x->bits = 232;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_b233_gx_words;

		// g->y
		group->g->y->bits = 233;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_b233_gy_words;

		goto binary_init;
	}
	break;
	case EC_NIST_B283:
	{
	ec_nist_b283:
		// cofactor (h)
		group->cofactor = 2;

		// p
		group->p->bits = 284;
		group->p->size = 40;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b283_p_words;

		// n
		group->n->bits = 282;
		group->n->size = 40;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b283_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b283_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 282;
		group->binary_parameters->b->size = 40;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_b283_b_words;

		// g->x
		group->g->x->bits = 283;
		group->g->x->size = 40;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_b283_gx_words;

		// g->y
		group->g->y->bits = 282;
		group->g->y->size = 40;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_b283_gy_words;

		goto binary_init;
	}
	break;
	case EC_NIST_B409:
	{
	ec_nist_b409:
		// cofactor (h)
		group->cofactor = 2;

		// p
		group->p->bits = 410;
		group->p->size = 56;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b409_p_words;

		// n
		group->n->bits = 409;
		group->n->size = 56;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b409_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b409_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 406;
		group->binary_parameters->b->size = 56;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_b409_b_words;

		// g->x
		group->g->x->bits = 409;
		group->g->x->size = 56;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_b409_gx_words;

		// g->y
		group->g->y->bits = 407;
		group->g->y->size = 56;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_b409_gy_words;

		goto binary_init;
	}
	break;
	case EC_NIST_B571:
	{
	ec_nist_b571:
		// cofactor (h)
		group->cofactor = 2;

		// p
		group->p->bits = 572;
		group->p->size = 72;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b571_p_words;

		// n
		group->n->bits = 570;
		group->n->size = 72;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b571_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b571_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 570;
		group->binary_parameters->b->size = 72;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)nist_b571_b_words;

		// g->x
		group->g->x->bits = 570;
		group->g->x->size = 72;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)nist_b571_gx_words;

		// g->y
		group->g->y->bits = 570;
		group->g->y->size = 72;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)nist_b571_gy_words;

		goto binary_init;
	}
	break;

	// SEC
	// Prime curves
	case EC_SECP_160K1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 160;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)secp_160k1_p_words;

		// n
		group->n->bits = 161;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)secp_160k1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 1;
		group->prime_parameters->a->size = 8;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)secp_160k1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 3;
		group->prime_parameters->b->size = 8;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)secp_160k1_b_words;

		// g->x
		group->g->x->bits = 158;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)secp_160k1_gx_words;

		// g->y
		group->g->y->bits = 160;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)secp_160k1_gy_words;

		goto prime_init;
	}
	break;
	case EC_SECP_160R1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 160;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)secp_160r1_p_words;

		// n
		group->n->bits = 161;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)secp_160r1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 160;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)secp_160r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 157;
		group->prime_parameters->b->size = 24;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)secp_160r1_b_words;

		// g->x
		group->g->x->bits = 159;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)secp_160r1_gx_words;

		// g->y
		group->g->y->bits = 158;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)secp_160r1_gy_words;

		goto prime_init;
	}
	break;
	case EC_SECP_160R2:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 160;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)secp_160r2_p_words;

		// n
		group->n->bits = 161;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)secp_160r2_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 160;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)secp_160r2_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 160;
		group->prime_parameters->b->size = 24;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)secp_160r2_b_words;

		// g->x
		group->g->x->bits = 159;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)secp_160r2_gx_words;

		// g->y
		group->g->y->bits = 160;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)secp_160r2_gy_words;

		goto prime_init;
	}
	break;
	case EC_SECP_192K1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 192;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)secp_192k1_p_words;

		// n
		group->n->bits = 192;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)secp_192k1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 1;
		group->prime_parameters->a->size = 8;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)secp_192k1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 2;
		group->prime_parameters->b->size = 8;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)secp_192k1_b_words;

		// g->x
		group->g->x->bits = 192;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)secp_192k1_gx_words;

		// g->y
		group->g->y->bits = 192;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)secp_192k1_gy_words;

		goto prime_init;
	}
	break;
	case EC_SECP_192R1:
		goto ec_nist_p192;
	case EC_SECP_224K1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 224;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)secp_224k1_p_words;

		// n
		group->n->bits = 225;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)secp_224k1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 1;
		group->prime_parameters->a->size = 8;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)secp_224k1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 3;
		group->prime_parameters->b->size = 8;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)secp_224k1_b_words;

		// g->x
		group->g->x->bits = 224;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)secp_224k1_gx_words;

		// g->y
		group->g->y->bits = 223;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)secp_224k1_gy_words;

		goto prime_init;
	}
	break;
	case EC_SECP_224R1:
		goto ec_nist_p224;
	case EC_SECP_256K1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 256;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)secp_256k1_p_words;

		// n
		group->n->bits = 256;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)secp_256k1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 1;
		group->prime_parameters->a->size = 8;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)secp_256k1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 3;
		group->prime_parameters->b->size = 8;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)secp_256k1_b_words;

		// g->x
		group->g->x->bits = 255;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)secp_256k1_gx_words;

		// g->y
		group->g->y->bits = 255;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)secp_256k1_gy_words;

		goto prime_init;
	}
	break;
	case EC_SECP_256R1:
		goto ec_nist_p256;
	case EC_SECP_384R1:
		goto ec_nist_p384;
	case EC_SECP_521R1:
		goto ec_nist_p521;

	// Binary curves
	case EC_SECT_163K1:
		goto ec_nist_k163;
	case EC_SECT_163R1:
	{
		// cofactor (h)
		group->cofactor = 2;

		// p
		group->p->bits = 164;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)sect_163r1_p_words;

		// n
		group->n->bits = 162;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)sect_163r1_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 163;
		group->binary_parameters->a->size = 24;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)sect_163r1_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 163;
		group->binary_parameters->b->size = 24;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)sect_163r1_b_words;

		// g->x
		group->g->x->bits = 162;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)sect_163r1_gx_words;

		// g->y
		group->g->y->bits = 159;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)sect_163r1_gy_words;

		goto binary_init;
	}
	break;
	case EC_SECT_163R2:
		goto ec_nist_b163;
	case EC_SECT_193R1:
	{
		// cofactor (h)
		group->cofactor = 2;

		// p
		group->p->bits = 194;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)sect_193r1_p_words;

		// n
		group->n->bits = 193;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)sect_193r1_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 189;
		group->binary_parameters->a->size = 24;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)sect_193r1_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 192;
		group->binary_parameters->b->size = 24;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)sect_193r1_b_words;

		// g->x
		group->g->x->bits = 193;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)sect_193r1_gx_words;

		// g->y
		group->g->y->bits = 190;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)sect_193r1_gy_words;

		goto binary_init;
	}
	break;
	case EC_SECT_193R2:
	{
		// cofactor (h)
		group->cofactor = 2;

		// p
		group->p->bits = 194;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)sect_193r2_p_words;

		// n
		group->n->bits = 193;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)sect_193r2_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 193;
		group->binary_parameters->a->size = 32;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)sect_193r2_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 192;
		group->binary_parameters->b->size = 24;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)sect_193r2_b_words;

		// g->x
		group->g->x->bits = 192;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)sect_193r2_gx_words;

		// g->y
		group->g->y->bits = 193;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)sect_193r2_gy_words;

		goto binary_init;
	}
	break;
	case EC_SECT_233K1:
		goto ec_nist_k233;
	case EC_SECT_233R1:
		goto ec_nist_b233;
	case EC_SECT_239K1:
	{
		// cofactor (h)
		group->cofactor = 4;

		// p
		group->p->bits = 240;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)sect_239k1_p_words;

		// n
		group->n->bits = 238;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)sect_239k1_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 1;
		group->binary_parameters->a->size = 8;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)sect_239k1_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 1;
		group->binary_parameters->b->size = 8;
		group->binary_parameters->b->sign = 1;
		group->binary_parameters->b->resize = 0;
		group->binary_parameters->b->flags = 0;
		group->binary_parameters->b->words = (bn_word_t *)sect_239k1_b_words;

		// g->x
		group->g->x->bits = 238;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)sect_239k1_gx_words;

		// g->y
		group->g->y->bits = 239;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)sect_239k1_gy_words;

		goto binary_init;
	}
	break;
	case EC_SECT_283K1:
		goto ec_nist_k283;
	case EC_SECT_283R1:
		goto ec_nist_b283;
	case EC_SECT_409K1:
		goto ec_nist_k409;
	case EC_SECT_409R1:
		goto ec_nist_b409;
	case EC_SECT_571K1:
		goto ec_nist_k571;
	case EC_SECT_571R1:
		goto ec_nist_b571;

	// Brainpool
	case EC_BRAINPOOL_160R1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 160;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_160r1_p_words;

		// n
		group->n->bits = 160;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_160r1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 158;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_160r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 157;
		group->prime_parameters->b->size = 24;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_160r1_b_words;

		// g->x
		group->g->x->bits = 160;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_160r1_gx_words;

		// g->y
		group->g->y->bits = 157;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_160r1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_160T1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 160;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_160t1_p_words;

		// n
		group->n->bits = 160;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_160t1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 160;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_160t1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 159;
		group->prime_parameters->b->size = 24;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_160t1_b_words;

		// g->x
		group->g->x->bits = 160;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_160t1_gx_words;

		// g->y
		group->g->y->bits = 160;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_160t1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_192R1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 192;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_192r1_p_words;

		// n
		group->n->bits = 192;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_192r1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 191;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_192r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 191;
		group->prime_parameters->b->size = 24;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_192r1_b_words;

		// g->x
		group->g->x->bits = 192;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_192r1_gx_words;

		// g->y
		group->g->y->bits = 189;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_192r1_gy_words;
		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_192T1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 192;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_192t1_p_words;

		// n
		group->n->bits = 192;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_192t1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 192;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_192t1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 189;
		group->prime_parameters->b->size = 24;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_192t1_b_words;

		// g->x
		group->g->x->bits = 190;
		group->g->x->size = 24;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_192t1_gx_words;

		// g->y
		group->g->y->bits = 188;
		group->g->y->size = 24;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_192t1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_224R1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 224;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_224r1_p_words;

		// n
		group->n->bits = 224;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_224r1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 223;
		group->prime_parameters->a->size = 32;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_224r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 222;
		group->prime_parameters->b->size = 32;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_224r1_b_words;

		// g->x
		group->g->x->bits = 220;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_224r1_gx_words;

		// g->y
		group->g->y->bits = 223;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_224r1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_224T1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 224;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_224t1_p_words;

		// n
		group->n->bits = 224;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_224t1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 224;
		group->prime_parameters->a->size = 32;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_224t1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 223;
		group->prime_parameters->b->size = 32;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_224t1_b_words;

		// g->x
		group->g->x->bits = 223;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_224t1_gx_words;

		// g->y
		group->g->y->bits = 218;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_224t1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_256R1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 256;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_256r1_p_words;

		// n
		group->n->bits = 256;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_256r1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 255;
		group->prime_parameters->a->size = 32;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_256r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 254;
		group->prime_parameters->b->size = 32;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_256r1_b_words;

		// g->x
		group->g->x->bits = 256;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_256r1_gx_words;

		// g->y
		group->g->y->bits = 255;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_256r1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_256T1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 256;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_256t1_p_words;

		// n
		group->n->bits = 256;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_256t1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 256;
		group->prime_parameters->a->size = 32;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_256t1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 255;
		group->prime_parameters->b->size = 32;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_256t1_b_words;

		// g->x
		group->g->x->bits = 256;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_256t1_gx_words;

		// g->y
		group->g->y->bits = 254;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_256t1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_320R1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 320;
		group->p->size = 40;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_320r1_p_words;

		// n
		group->n->bits = 320;
		group->n->size = 40;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_320r1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 318;
		group->prime_parameters->a->size = 40;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_320r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 319;
		group->prime_parameters->b->size = 40;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_320r1_b_words;

		// g->x
		group->g->x->bits = 319;
		group->g->x->size = 40;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_320r1_gx_words;

		// g->y
		group->g->y->bits = 317;
		group->g->y->size = 40;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_320r1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_320T1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 320;
		group->p->size = 40;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_320t1_p_words;

		// n
		group->n->bits = 320;
		group->n->size = 40;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_320t1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 320;
		group->prime_parameters->a->size = 40;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_320t1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 320;
		group->prime_parameters->b->size = 40;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_320t1_b_words;

		// g->x
		group->g->x->bits = 320;
		group->g->x->size = 40;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_320t1_gx_words;

		// g->y
		group->g->y->bits = 319;
		group->g->y->size = 40;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_320t1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_384R1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 384;
		group->p->size = 48;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_384r1_p_words;

		// n
		group->n->bits = 384;
		group->n->size = 48;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_384r1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 383;
		group->prime_parameters->a->size = 48;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_384r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 379;
		group->prime_parameters->b->size = 48;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_384r1_b_words;

		// g->x
		group->g->x->bits = 381;
		group->g->x->size = 48;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_384r1_gx_words;

		// g->y
		group->g->y->bits = 384;
		group->g->y->size = 48;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_384r1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_384T1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 384;
		group->p->size = 48;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_384t1_p_words;

		// n
		group->n->bits = 384;
		group->n->size = 48;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_384t1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 384;
		group->prime_parameters->a->size = 48;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_384t1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 383;
		group->prime_parameters->b->size = 48;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_384t1_b_words;

		// g->x
		group->g->x->bits = 381;
		group->g->x->size = 48;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_384t1_gx_words;

		// g->y
		group->g->y->bits = 382;
		group->g->y->size = 48;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_384t1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_512R1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 512;
		group->p->size = 64;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_512r1_p_words;

		// n
		group->n->bits = 512;
		group->n->size = 64;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_512r1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 511;
		group->prime_parameters->a->size = 64;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_512r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 510;
		group->prime_parameters->b->size = 64;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_512r1_b_words;

		// g->x
		group->g->x->bits = 512;
		group->g->x->size = 64;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_512r1_gx_words;

		// g->y
		group->g->y->bits = 511;
		group->g->y->size = 64;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_512r1_gy_words;

		goto prime_init;
	}
	break;
	case EC_BRAINPOOL_512T1:
	{
		// cofactor (h)
		group->cofactor = 1;

		// p
		group->p->bits = 512;
		group->p->size = 64;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)brainpool_512t1_p_words;

		// n
		group->n->bits = 512;
		group->n->size = 64;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)brainpool_512t1_n_words;

		// prime_parameters->a
		group->prime_parameters->a->bits = 512;
		group->prime_parameters->a->size = 64;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_512t1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 511;
		group->prime_parameters->b->size = 64;
		group->prime_parameters->b->sign = 1;
		group->prime_parameters->b->resize = 0;
		group->prime_parameters->b->flags = 0;
		group->prime_parameters->b->words = (bn_word_t *)brainpool_512t1_b_words;

		// g->x
		group->g->x->bits = 511;
		group->g->x->size = 64;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)brainpool_512t1_gx_words;

		// g->y
		group->g->y->bits = 511;
		group->g->y->size = 64;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)brainpool_512t1_gy_words;

		goto prime_init;
	}
	break;

	// Montgomery
	case EC_CURVE25519:
	{
		// cofactor (h)
		group->cofactor = 8;

		// p
		group->p->bits = 255;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)curve25519_p_words;

		// n
		group->n->bits = 253;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)curve25519_n_words;

		// montgomery_parameters->a
		group->montgomery_parameters->a->bits = 19;
		group->montgomery_parameters->a->size = 8;
		group->montgomery_parameters->a->sign = 1;
		group->montgomery_parameters->a->resize = 0;
		group->montgomery_parameters->a->flags = 0;
		group->montgomery_parameters->a->words = (bn_word_t *)curve25519_a_words;

		// montgomery_parameters->b
		group->montgomery_parameters->b->bits = 1;
		group->montgomery_parameters->b->size = 8;
		group->montgomery_parameters->b->sign = 1;
		group->montgomery_parameters->b->resize = 0;
		group->montgomery_parameters->b->flags = 0;
		group->montgomery_parameters->b->words = (bn_word_t *)curve25519_b_words;

		// g->x
		group->g->x->bits = 4;
		group->g->x->size = 8;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)curve25519_gx_words;

		// g->y
		group->g->y->bits = 254;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)curve25519_gy_words;

		goto montgomery_init;
	}
	break;
	case EC_CURVE448:
	{
		// cofactor (h)
		group->cofactor = 4;

		// p
		group->p->bits = 448;
		group->p->size = 56;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)curve448_p_words;

		// n
		group->n->bits = 446;
		group->n->size = 56;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)curve448_n_words;

		// montgomery_parameters->a
		group->montgomery_parameters->a->bits = 18;
		group->montgomery_parameters->a->size = 8;
		group->montgomery_parameters->a->sign = 1;
		group->montgomery_parameters->a->resize = 0;
		group->montgomery_parameters->a->flags = 0;
		group->montgomery_parameters->a->words = (bn_word_t *)curve448_a_words;

		// montgomery_parameters->b
		group->montgomery_parameters->b->bits = 1;
		group->montgomery_parameters->b->size = 8;
		group->montgomery_parameters->b->sign = 1;
		group->montgomery_parameters->b->resize = 0;
		group->montgomery_parameters->b->flags = 0;
		group->montgomery_parameters->b->words = (bn_word_t *)curve448_b_words;

		// g->x
		group->g->x->bits = 3;
		group->g->x->size = 8;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)curve448_gx_words;

		// g->y
		group->g->y->bits = 447;
		group->g->y->size = 56;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)curve448_gy_words;

		goto montgomery_init;
	}
	break;

	// Twisted Edwards
	case EC_ED25519:
	{
		// cofactor (h)
		group->cofactor = 8;

		// p
		group->p->bits = 255;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)ed25519_p_words;

		// n
		group->n->bits = 253;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)ed25519_n_words;

		// edwards_parameters->a
		group->edwards_parameters->a->bits = 255;
		group->edwards_parameters->a->size = 32;
		group->edwards_parameters->a->sign = 1;
		group->edwards_parameters->a->resize = 0;
		group->edwards_parameters->a->flags = 0;
		group->edwards_parameters->a->words = (bn_word_t *)ed25519_a_words;

		// edwards_parameters->d
		group->edwards_parameters->d->bits = 255;
		group->edwards_parameters->d->size = 32;
		group->edwards_parameters->d->sign = 1;
		group->edwards_parameters->d->resize = 0;
		group->edwards_parameters->d->flags = 0;
		group->edwards_parameters->d->words = (bn_word_t *)ed25519_d_words;

		// g->x
		group->g->x->bits = 254;
		group->g->x->size = 32;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)ed25519_gx_words;

		// g->y
		group->g->y->bits = 255;
		group->g->y->size = 32;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)ed25519_gy_words;

		group->_encode = ec_ed25519_point_encode;
		group->_decode = ec_ed25519_point_decode;

		goto edwards_init;
	}
	break;
	case EC_ED448:
	{
		// cofactor (h)
		group->cofactor = 4;

		// p
		group->p->bits = 448;
		group->p->size = 56;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)ed448_p_words;

		// n
		group->n->bits = 446;
		group->n->size = 56;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)ed448_n_words;

		// edwards_parameters->a
		group->edwards_parameters->a->bits = 1;
		group->edwards_parameters->a->size = 8;
		group->edwards_parameters->a->sign = 1;
		group->edwards_parameters->a->resize = 0;
		group->edwards_parameters->a->flags = 0;
		group->edwards_parameters->a->words = (bn_word_t *)ed448_a_words;

		// edwards_parameters->d
		group->edwards_parameters->d->bits = 448;
		group->edwards_parameters->d->size = 56;
		group->edwards_parameters->d->sign = 1;
		group->edwards_parameters->d->resize = 0;
		group->edwards_parameters->d->flags = 0;
		group->edwards_parameters->d->words = (bn_word_t *)ed448_d_words;

		// g->x
		group->g->x->bits = 447;
		group->g->x->size = 56;
		group->g->x->sign = 1;
		group->g->x->resize = 0;
		group->g->x->flags = 0;
		group->g->x->words = (bn_word_t *)ed448_gx_words;

		// g->y
		group->g->y->bits = 447;
		group->g->y->size = 56;
		group->g->y->sign = 1;
		group->g->y->resize = 0;
		group->g->y->flags = 0;
		group->g->y->words = (bn_word_t *)ed448_gy_words;

		group->_encode = ec_ed448_point_encode;
		group->_decode = ec_ed448_point_decode;

		goto edwards_init;
	}
	break;

	default:
		break;
	}

end:
	return group;

prime_init:
	group->_add = ec_prime_point_add;
	group->_double = ec_prime_point_double;
	group->_multiply = ec_prime_point_multiply;
	group->_on_curve = ec_prime_point_on_curve;
	group->_is_identity = ec_prime_point_at_infinity;
	group->_encode = ec_prime_point_encode;
	group->_decode = ec_prime_point_decode;
	goto end;

edwards_init:
	group->_add = ec_edwards_point_add;
	group->_double = ec_edwards_point_double;
	group->_multiply = ec_edwards_point_multiply;
	group->_on_curve = ec_edwards_point_on_curve;
	group->_is_identity = ec_edwards_point_is_identity;
	goto end;
binary_init:
	goto end;
montgomery_init:
	goto end;
}

void ec_group_delete(ec_group *eg)
{
	bignum_ctx_delete(eg->bctx);
	free(eg);
}
