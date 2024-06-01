/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include <round.h>

bignum_t *bignum_init(void *ptr, size_t size, uint32_t bits)
{
	bignum_t *bn = (bignum_t *)ptr;
	size_t required_size = sizeof(bignum_t);

	bits = ROUND_UP(bits, 64);
	required_size += bits / 8;

	if (size < required_size)
	{
		return NULL;
	}

	memset(bn, 0, required_size);

	if (bits > 0)
	{
		bn->bits = bits;
		bn->qwords = (uint64_t *)((byte_t *)bn + sizeof(bignum_t));
	}

	return bn;
}

bignum_t *bignum_new(uint32_t bits)
{
	bignum_t *bn = NULL;
	size_t size = sizeof(bignum_t);

	bits = ROUND_UP(bits, 64);
	size += bits / 8;

	bn = (bignum_t *)malloc(size);

	if (bn == NULL)
	{
		return NULL;
	}

	memset(bn, 0, size);

	if (bits > 0)
	{
		bn->bits = bits;
		bn->qwords = (uint64_t *)((byte_t *)bn + sizeof(bignum_t));
	}

	return bn;
}

void bignum_free(bignum_t *bn)
{
	if (bn == NULL)
	{
		return;
	}

	if (bn->resize)
	{
		free(bn->qwords);
	}

	free(bn);
}

void bignum_secure_free(bignum_t *bn)
{
	if (bn == NULL)
	{
		return;
	}

	if (bn->resize)
	{
		free(bn->qwords);
	}

	free(bn);
}

void bignum_set(bignum_t *bn, uint64_t value)
{
	bn->qwords[0] = value;
}
