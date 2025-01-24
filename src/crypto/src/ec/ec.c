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
		return 160;
	case EC_BRAINPOOL_160T1:
		return 160;
	case EC_BRAINPOOL_192R1:
		return 192;
	case EC_BRAINPOOL_192T1:
		return 192;
	case EC_BRAINPOOL_224R1:
		return 224;
	case EC_BRAINPOOL_224T1:
		return 224;
	case EC_BRAINPOOL_256R1:
		return 256;
	case EC_BRAINPOOL_256T1:
		return 256;
	case EC_BRAINPOOL_320R1:
		return 320;
	case EC_BRAINPOOL_320T1:
		return 320;
	case EC_BRAINPOOL_384R1:
		return 384;
	case EC_BRAINPOOL_384T1:
		return 384;
	case EC_BRAINPOOL_512R1:
		return 512;
	case EC_BRAINPOOL_512T1:
		return 512;

	// Special
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

		// prime_paramters->a
		group->prime_parameters->a->bits = 192;
		group->prime_parameters->a->size = 24;
		group->prime_parameters->a->sign = 1;
		group->prime_parameters->a->resize = 0;
		group->prime_parameters->a->flags = 0;
		group->prime_parameters->a->words = (bn_word_t *)nist_p192_a_words;

		// prime_paramters->b
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
	case EC_NIST_P224:
		break;
	case EC_NIST_P256:
	{
		ec_prime_curve *paramters = malloc(sizeof(ec_prime_curve) + (2 * bignum_size(bits)));

		if (paramters == NULL)
		{
			free(group);
			return NULL;
		}

		paramters->a = PTR_OFFSET(paramters, sizeof(ec_prime_curve));
		paramters->b = PTR_OFFSET(paramters, sizeof(ec_prime_curve) + bignum_size(bits));

		bignum_init(paramters->a, bignum_size(bits), bits);
		bignum_init(paramters->b, bignum_size(bits), bits);

		paramters->a = bignum_set_hex(paramters->a, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 64);
		paramters->b = bignum_set_hex(paramters->b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 64);

		group->parameters = paramters;

		group->p = bignum_set_hex(NULL, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 64);
		group->n = bignum_set_hex(NULL, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 64);

		group->g = malloc(sizeof(ec_point));

		if (group->g == NULL)
		{
			return NULL;
		}

		group->g->x = bignum_set_hex(NULL, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 64);
		group->g->y = bignum_set_hex(NULL, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 64);
	}
	break;
	case EC_NIST_P384:
	case EC_NIST_P521:

	// SECG
	case EC_SECP_160K1:
	case EC_SECP_160R1:
	case EC_SECP_160R2:
	case EC_SECP_192K1:
	case EC_SECP_224K1:
	case EC_SECP_256K1:
		break;

	// Brainpool
	case EC_BRAINPOOL_160R1:
	case EC_BRAINPOOL_160T1:
	case EC_BRAINPOOL_192R1:
	case EC_BRAINPOOL_192T1:
	case EC_BRAINPOOL_224R1:
	case EC_BRAINPOOL_224T1:
	case EC_BRAINPOOL_256R1:
	case EC_BRAINPOOL_256T1:
	case EC_BRAINPOOL_320R1:
	case EC_BRAINPOOL_320T1:
	case EC_BRAINPOOL_384R1:
	case EC_BRAINPOOL_384T1:
	case EC_BRAINPOOL_512R1:
	case EC_BRAINPOOL_512T1:
		break;

	// Twisted Edwards
	case EC_ED25519:
	case EC_ED448:
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
