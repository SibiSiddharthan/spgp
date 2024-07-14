/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <round.h>
#include <minmax.h>

bignum_t *bignum_modadd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m)
{
	bignum_t *temp = NULL;
	uint32_t required_bits = m->bits;
	uint32_t op_bits = MAX(a->bits, b->bits) + 1;

	// Check zero.
	if (m->bits == 0)
	{
		return NULL;
	}

	temp = bignum_add(NULL, a, b);
	r = bignum_resize(r, required_bits);

	if (temp == NULL || r == NULL)
	{
		return NULL;
	}

	r = bignum_mod(r, temp, m);
	bignum_delete(temp);

	if (r == NULL)
	{
		return NULL;
	}

	return r;
}

bignum_t *bignum_modsub(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m)
{
	bignum_t *temp = NULL;
	uint32_t required_bits = m->bits;
	uint32_t op_bits = MAX(a->bits, b->bits) + 1;

	// Check zero.
	if (m->bits == 0)
	{
		return NULL;
	}

	temp = bignum_sub(NULL, a, b);
	r = bignum_resize(r, required_bits);

	if (temp == NULL || r == NULL)
	{
		return NULL;
	}

	r = bignum_mod(r, temp, m);
	bignum_delete(temp);

	if (r == NULL)
	{
		return NULL;
	}

	return r;
}
