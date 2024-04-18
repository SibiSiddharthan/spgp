/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>

#define ROUNDUP(x, y) ((((x) + ((y)-1)) / (y)) * (y))

bignum_t *bignum_new(uint32_t bits)
{
	bignum_t *bn = NULL;
	size_t size = sizeof(bignum_t);

	if (bits == 0)
	{
		return NULL;
	}

	bits = ROUNDUP(bits, 64);
	size += bits / 8;

	bn = (bignum_t *)malloc(size);

	if (bn == NULL)
	{
		return NULL;
	}

	memset(bn, 0, size);

	bn->bits = bits;
	bn->size = size - sizeof(bignum_t);
	bn->qwords = (uint64_t *)((byte_t *)bn + sizeof(bignum_t));

	return bn;
}

void bignum_free(bignum_t *bn)
{
	if (bn == NULL)
	{
		return;
	}

	free(bn);
}

void bignum_secure_free(bignum_t *bn)
{
	if (bn == NULL)
	{
		return;
	}

	memset(bn, 0, bn->size + sizeof(bignum_t));
	free(bn);
}

void bignum_set(bignum_t *bn, uint64_t value)
{
	bn->qwords[0] = value;
}
