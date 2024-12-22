/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <bignum.h>
#include <ec.h>

#include <ptr.h>

#include <string.h>

uint32_t ec_edwards_point_is_identity(ec_point *a)
{
	// (x,y) = (0,1)
	if (a->x->bits == 0 && a->y->bits == 1)
	{
		return 1;
	}

	return 0;
}

uint32_t ec_edwards_point_on_curve(ec_group *eg, ec_point *a)
{
	uint32_t result = 0;
	ec_edwards_curve *parameters = eg->parameters;

	bignum_t *lhs = NULL, *rhs = NULL;
	bignum_t *xsq = NULL, *ysq = NULL;

	bignum_ctx_start(eg->bctx, 2 * bignum_size(eg->bits) + 2 * bignum_size(eg->bits * 2));

	lhs = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);
	rhs = bignum_ctx_allocate_bignum(eg->bctx, eg->bits);
	xsq = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);
	ysq = bignum_ctx_allocate_bignum(eg->bctx, eg->bits * 2);

	xsq = bignum_sqr(eg->bctx, xsq, a->x);
	ysq = bignum_sqr(eg->bctx, ysq, a->y);

	// Compute (ax^2 + y^2) % p
	lhs = bignum_modmul(eg->bctx, lhs, xsq, parameters->a, eg->p);
	lhs = bignum_modadd(eg->bctx, lhs, lhs, ysq, eg->p);

	// Compute (1 + d*x^2*y^2) % p
	rhs = bignum_modmul(eg->bctx, rhs, xsq, ysq, eg->p);
	rhs = bignum_modmul(eg->bctx, rhs, rhs, parameters->d, eg->p);
	rhs = bignum_uadd_word(rhs, rhs, 1);

	// Compare
	if (bignum_cmp(lhs, rhs) == 0)
	{
		result = 1;
	}

	bignum_ctx_end(eg->bctx);

	return result;
}
