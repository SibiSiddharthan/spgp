/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>
#include <bignum-internal.h>

bignum_t *bignum_lcm(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b)
{
	uint32_t required_bits = a->bits + b->bits;
	bignum_ctx *obctx = bctx;
	bignum_t *gcd = NULL;

	r = bignum_resize(r, required_bits);

	// Handle zero
	if (a->bits == 0 || b->bits == 0)
	{
		bignum_zero(r);
		return r;
	}

	if (r == NULL)
	{
		return NULL;
	}

	if (obctx == NULL)
	{
		bctx = bignum_ctx_new(0);

		if (bctx == NULL)
		{
			return NULL;
		}
	}

	bignum_ctx_start(bctx, bignum_size(MIN(a->bits, b->bits)));

	gcd = bignum_ctx_allocate_bignum(bctx, MIN(a->bits, b->bits));

	r = bignum_mul(bctx, r, a, b);
	gcd = bignum_gcd(bctx, gcd, a, b);
	r = bignum_div(bctx, r, r, gcd);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return r;
}
