/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>
#include <drbg.h>

bignum_t *bignum_rand(void *drbg, bignum_t *bn, uint32_t bits)
{
	uint32_t status = 0;
	drbg_ctx *rbctx = drbg;

	bn = bignum_resize(bn, bits);

	if (bn == NULL)
	{
		return NULL;
	}

	if (rbctx == NULL)
	{
		rbctx = get_default_drbg();
	}

	status = drbg_generate(rbctx, 0, NULL, 0, bn->words, CEIL_DIV(bits, 8));

	if (status == 0)
	{
		return NULL;
	}

	bn->bits = bignum_bitcount(bn);

	return bn;
}

bignum_t *bignum_rand_max(void *drbg, bignum_t *bn, bignum_t *limit)
{
	uint32_t status = 0;
	drbg_ctx *rbctx = drbg;

	bn = bignum_resize(bn, limit->bits);

	if (bn == NULL)
	{
		return NULL;
	}

	if (rbctx == NULL)
	{
		rbctx = get_default_drbg();
	}

	while (1)
	{
		status = drbg_generate(rbctx, 0, NULL, 0, bn->words, CEIL_DIV(limit->bits, 8));

		if (status == 0)
		{
			return NULL;
		}

		bn->bits = bignum_bitcount(bn);

		// bn > limit
		if (bignum_cmp_abs(bn, limit) >= 0)
		{
			continue;
		}

		// Don't allow zero
		if (bn->bits == 0)
		{
			continue;
		}

		break;
	}

	return bn;
}
