/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <bignum.h>
#include <ec.h>

// NIST P-192
bn_word_t nist_p192_p_words[3] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF};
bn_word_t nist_p192_a_words[3] = {0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF};
bn_word_t nist_p192_b_words[3] = {0xFEB8DEECC146B9B1, 0x0FA7E9AB72243049, 0xFEB8DEECC146B9B1};
bn_word_t nist_p192_gx_words[3] = {0xF4FF0AFD82FF1012, 0x7CBF20EB43A18800, 0x188DA80EB03090F6};
bn_word_t nist_p192_gy_words[3] = {0x73F977A11E794811, 0x631011ED6B24CDD5, 0x07192B95FFC8DA78};

bignum_t nist_p192_p = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_p_words};
bignum_t nist_p192_a = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_a_words};
bignum_t nist_p192_b = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_b_words};
bignum_t nist_p192_gx = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_gx_words};
bignum_t nist_p192_gy = {.bits = 187, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_gy_words};

const ec_prime_curve ec_nist_p192 = {.p = &nist_p192_p, .a = &nist_p192_a, .b = &nist_p192_b, .gx = &nist_p192_gx, .gy = &nist_p192_gy};

uint32_t ec_prime_point_check(ec_group *eg, ec_point *a)
{
	uint32_t result = 0;
	ec_prime_curve *parameters = eg->parameters;

	bignum_t *lhs = NULL;
	bignum_t *rhs = NULL;
	bignum_t *xcube = NULL;

	bignum_ctx_start(eg->bctx, bignum_size(parameters->p->bits * 6));

	lhs = bignum_ctx_allocate_bignum(eg->bctx, parameters->p->bits);
	rhs = bignum_ctx_allocate_bignum(eg->bctx, parameters->p->bits * 2);
	xcube = bignum_ctx_allocate_bignum(eg->bctx, parameters->p->bits * 3);

	// Compute y^2 % p
	lhs = bignum_modsqr(eg->bctx, lhs, a->y, parameters->p);

	// Compute Ax + B % p
	rhs = bignum_mul(eg->bctx, rhs, a->x, parameters->a);
	rhs = bignum_modadd(eg->bctx, rhs, rhs, parameters->b, parameters->p);

	// Compute x^3 %p
	xcube = bignum_sqr(eg->bctx, xcube, a->x);
	xcube = bignum_modmul(eg->bctx, xcube, xcube, a->x, parameters->p);

	rhs = bignum_modadd(eg->bctx, rhs, xcube, rhs, parameters->p);

	// Compare
	if (bignum_cmp(lhs, rhs) == 0)
	{
		result = 1;
	}

	bignum_ctx_end(eg->bctx);

	return result;
}
