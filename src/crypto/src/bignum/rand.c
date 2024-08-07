/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <round.h>
#include <drbg.h>

bignum_t *bignum_rand(bignum_t *bn, void *drbg, uint32_t bits)
{
	int32_t status = 0;
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

	if (status != 0)
	{
		return NULL;
	}

	return 0;
}
