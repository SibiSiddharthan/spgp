/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <bignum.h>
#include <ec.h>

#include <ptr.h>
#include <round.h>

#include <stdlib.h>
#include <string.h>

#include "curves/prime.h"
#include "curves/binary.h"
#include "curves/brainpool.h"
#include "curves/montgomery.h"
#include "curves/edwards.h"

size_t ec_group_size(uint32_t bits);

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

	// SECG
	case EC_SECP_160K1:
		return 160;
	case EC_SECP_160R1:
		return 160;
	case EC_SECP_160R2:
		return 160;
	case EC_SECP_192K1:
		return 192;
	case EC_SECP_224K1:
		return 224;
	case EC_SECP_256K1:
		return 256;

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

	if (bits == 0)
	{
		return NULL;
	}

	group = malloc(sizeof(ec_group));

	if (group == NULL)
	{
		return NULL;
	}

	group->bits = bits;
	group->bctx = bignum_ctx_new(32 * bignum_size(bits));

	switch (id)
	{
	// NIST
	// Prime curves
	case EC_NIST_P192:
	{
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
		group->prime_parameters->b->bits = 192;
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
	}
	break;
	case EC_NIST_P224:
	{
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
	}
	break;
	case EC_NIST_P256:
	{
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
		group->prime_parameters->b->bits = 256;
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
	}
	break;
	case EC_NIST_P384:
	{
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
	}
	break;
	case EC_NIST_P521:
	{
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
		group->prime_parameters->b->bits = 521;
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
	}
	break;

	// Binary curves (Koblitz)
	case EC_NIST_K163:
	{
		// p
		group->p->bits = 164;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k163_p_words;

		// n
		group->n->bits = 164;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k163_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 164;
		group->binary_parameters->a->size = 24;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k163_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 164;
		group->binary_parameters->b->size = 24;
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
	}
	break;
	case EC_NIST_K233:
	{
		// p
		group->p->bits = 234;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k233_p_words;

		// n
		group->n->bits = 234;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k233_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 234;
		group->binary_parameters->a->size = 32;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k233_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 234;
		group->binary_parameters->b->size = 32;
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
	}
	break;
	case EC_NIST_K283:
	{
		// p
		group->p->bits = 284;
		group->p->size = 40;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k283_p_words;

		// n
		group->n->bits = 284;
		group->n->size = 40;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k283_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 284;
		group->binary_parameters->a->size = 40;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k283_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 284;
		group->binary_parameters->b->size = 40;
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
	}
	break;
	case EC_NIST_K409:
	{
		// p
		group->p->bits = 410;
		group->p->size = 56;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k409_p_words;

		// n
		group->n->bits = 410;
		group->n->size = 56;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k409_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 410;
		group->binary_parameters->a->size = 56;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k409_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 410;
		group->binary_parameters->b->size = 56;
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
	}
	break;
	case EC_NIST_K571:
	{
		// p
		group->p->bits = 572;
		group->p->size = 72;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_k571_p_words;

		// n
		group->n->bits = 572;
		group->n->size = 72;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_k571_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 572;
		group->binary_parameters->a->size = 72;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_k571_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 572;
		group->binary_parameters->b->size = 72;
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
	}
	break;

	// Binary curves (Psuedo random)
	case EC_NIST_B163:
	{
		// p
		group->p->bits = 164;
		group->p->size = 24;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b163_p_words;

		// n
		group->n->bits = 164;
		group->n->size = 24;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b163_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 164;
		group->binary_parameters->a->size = 24;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b163_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 164;
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
	}
	break;
	case EC_NIST_B233:
	{
		// p
		group->p->bits = 234;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b233_p_words;

		// n
		group->n->bits = 234;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b233_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 234;
		group->binary_parameters->a->size = 32;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b233_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 234;
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
	}
	break;
	case EC_NIST_B283:
	{
		// p
		group->p->bits = 284;
		group->p->size = 40;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b283_p_words;

		// n
		group->n->bits = 284;
		group->n->size = 40;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b283_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 284;
		group->binary_parameters->a->size = 40;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b283_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 284;
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
	}
	break;
	case EC_NIST_B409:
	{
		// p
		group->p->bits = 410;
		group->p->size = 56;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b409_p_words;

		// n
		group->n->bits = 410;
		group->n->size = 56;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b409_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 410;
		group->binary_parameters->a->size = 56;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b409_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 410;
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
	}
	break;
	case EC_NIST_B571:
	{
		// p
		group->p->bits = 572;
		group->p->size = 72;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)nist_b571_p_words;

		// n
		group->n->bits = 572;
		group->n->size = 72;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)nist_b571_n_words;

		// binary_parameters->a
		group->binary_parameters->a->bits = 572;
		group->binary_parameters->a->size = 72;
		group->binary_parameters->a->sign = 1;
		group->binary_parameters->a->resize = 0;
		group->binary_parameters->a->flags = 0;
		group->binary_parameters->a->words = (bn_word_t *)nist_b571_a_words;

		// binary_parameters->b
		group->binary_parameters->b->bits = 572;
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
	}
	break;

	// Brainpool
	case EC_BRAINPOOL_160R1:
	{
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
		group->prime_parameters->a->bits = 160;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_160r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 160;
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
	}
	break;
	case EC_BRAINPOOL_160T1:
	{
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
		group->prime_parameters->b->bits = 160;
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
	}
	break;
	case EC_BRAINPOOL_192R1:
	{
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
		group->prime_parameters->a->bits = 192;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_192r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 192;
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
	}
	break;
	case EC_BRAINPOOL_192T1:
	{
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
		group->prime_parameters->b->bits = 192;
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
	}
	break;
	case EC_BRAINPOOL_224R1:
	{
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
		group->prime_parameters->a->bits = 224;
		group->prime_parameters->a->size = 32;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_224r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 224;
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
	}
	break;
	case EC_BRAINPOOL_224T1:
	{
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
		group->prime_parameters->b->bits = 224;
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
	}
	break;
	case EC_BRAINPOOL_256R1:
	{
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
		group->prime_parameters->a->bits = 256;
		group->prime_parameters->a->size = 32;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_256r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 256;
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
	}
	break;
	case EC_BRAINPOOL_256T1:
	{
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
		group->prime_parameters->b->bits = 256;
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
	}
	break;
	case EC_BRAINPOOL_320R1:
	{
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
		group->prime_parameters->a->bits = 320;
		group->prime_parameters->a->size = 40;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_320r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 320;
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
	}
	break;
	case EC_BRAINPOOL_320T1:
	{
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
	}
	break;
	case EC_BRAINPOOL_384R1:
	{
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
		group->prime_parameters->a->bits = 384;
		group->prime_parameters->a->size = 48;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_384r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 384;
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
	}
	break;
	case EC_BRAINPOOL_384T1:
	{
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
		group->prime_parameters->b->bits = 384;
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
	}
	break;
	case EC_BRAINPOOL_512R1:
	{
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
		group->prime_parameters->a->bits = 512;
		group->prime_parameters->a->size = 64;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)brainpool_512r1_a_words;

		// prime_parameters->b
		group->prime_parameters->b->bits = 512;
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
	}
	break;
	case EC_BRAINPOOL_512T1:
	{
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
		group->prime_parameters->b->bits = 512;
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
	}
	break;

	// Montgomery
	case EC_CURVE25519:
	{
		// p
		group->p->bits = 255;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)curve25519_p_words;

		// n
		group->n->bits = 255;
		group->n->size = 32;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)curve25519_n_words;

		// montgomery_parameters->a
		group->montgomery_parameters->a->bits = 255;
		group->montgomery_parameters->a->size = 32;
		group->montgomery_parameters->a->sign = 1;
		group->montgomery_parameters->a->resize = 0;
		group->montgomery_parameters->a->flags = 0;
		group->montgomery_parameters->a->words = (bn_word_t *)curve25519_a_words;

		// montgomery_parameters->b
		group->montgomery_parameters->b->bits = 255;
		group->montgomery_parameters->b->size = 32;
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
	}
	break;
	case EC_CURVE448:
	{
		// p
		group->p->bits = 448;
		group->p->size = 56;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)curve448_p_words;

		// n
		group->n->bits = 448;
		group->n->size = 56;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)curve448_n_words;

		// montgomery_parameters->a
		group->montgomery_parameters->a->bits = 448;
		group->montgomery_parameters->a->size = 56;
		group->montgomery_parameters->a->sign = 1;
		group->montgomery_parameters->a->resize = 0;
		group->montgomery_parameters->a->flags = 0;
		group->montgomery_parameters->a->words = (bn_word_t *)curve448_a_words;

		// montgomery_parameters->b
		group->montgomery_parameters->b->bits = 448;
		group->montgomery_parameters->b->size = 56;
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
	}
	break;

	// Twisted Edwards
	case EC_ED25519:
	{
		// p
		group->p->bits = 255;
		group->p->size = 32;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)ed25519_p_words;

		// n
		group->n->bits = 255;
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

		// edwards_parameters->b
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
	}
	break;
	case EC_ED448:
	{
		// p
		group->p->bits = 448;
		group->p->size = 56;
		group->p->sign = 1;
		group->p->resize = 0;
		group->p->flags = 0;
		group->p->words = (bn_word_t *)ed448_p_words;

		// n
		group->n->bits = 448;
		group->n->size = 56;
		group->n->sign = 1;
		group->n->resize = 0;
		group->n->flags = 0;
		group->n->words = (bn_word_t *)ed448_n_words;

		// edwards_parameters->a
		group->edwards_parameters->a->bits = 448;
		group->edwards_parameters->a->size = 56;
		group->edwards_parameters->a->sign = 1;
		group->edwards_parameters->a->resize = 0;
		group->edwards_parameters->a->flags = 0;
		group->edwards_parameters->a->words = (bn_word_t *)ed448_a_words;

		// edwards_parameters->b
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
	}
	break;

	default:
		break;
	}

	return group;
}

void ec_group_delete(ec_group *eg)
{
	bignum_ctx_delete(eg->bctx);
	free(eg->parameters);
	free(eg);
}

ec_point *ec_point_new(ec_group *eg)
{
	ec_point *point = NULL;
	uint32_t bits = eg->bits;

	point = malloc(sizeof(ec_point) + (2 * bignum_size(bits)));

	if (point == NULL)
	{
		return NULL;
	}

	memset(point, 0, sizeof(ec_point) + (2 * bignum_size(bits)));

	point->x = PTR_OFFSET(point, sizeof(ec_point));
	bignum_init(point->x, bignum_size(bits), bits);

	point->y = PTR_OFFSET(point, sizeof(ec_point) + bignum_size(bits));
	bignum_init(point->y, bignum_size(bits), bits);

	return point;
}

ec_point *ec_point_copy(ec_point *dst, ec_point *src)
{
	void *result = NULL;

	if (dst == src)
	{
		return dst;
	}

	result = bignum_copy(dst->x, src->x);

	if (result == NULL)
	{
		return NULL;
	}

	result = bignum_copy(dst->y, src->y);

	if (result == NULL)
	{
		return NULL;
	}

	return dst;
}

void ec_point_infinity(ec_group *g, ec_point *r)
{
	bignum_zero(r->x);
	bignum_zero(r->y);
}

void ec_point_delete(ec_point *ep)
{
	free(ep);
}
