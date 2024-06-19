/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include <bitscan.h>
#include <round.h>

bignum_t *bignum_init(void *ptr, size_t size, uint32_t bits)
{
	bignum_t *bn = (bignum_t *)ptr;
	size_t required_size = sizeof(bignum_t);

	bits = ROUND_UP(bits, BIGNUM_BITS_PER_WORD);
	required_size += bits / 8;

	if (size < required_size)
	{
		return NULL;
	}

	memset(bn, 0, required_size);

	bn->bits = 0;
	bn->sign = 1;

	if (bits > 0)
	{
		bn->size = CEIL_DIV(bits, 8);
		bn->words = (uint64_t *)((byte_t *)bn + sizeof(bignum_t));
	}

	return bn;
}

bignum_t *bignum_new(uint32_t bits)
{
	bignum_t *bn = NULL;
	size_t size = sizeof(bignum_t);

	bits = ROUND_UP(bits, BIGNUM_BITS_PER_WORD);
	size += bits / 8;

	bn = (bignum_t *)malloc(size);

	if (bn == NULL)
	{
		return NULL;
	}

	memset(bn, 0, size);

	bn->bits = 0;
	bn->sign = 1;

	if (bits > 0)
	{
		bn->size = CEIL_DIV(bits, 8);
		bn->words = (uint64_t *)((byte_t *)bn + sizeof(bignum_t));
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
		free(bn->words);
	}

	free(bn);
}

bignum_t *bignum_copy(void *ptr, size_t size, bignum_t *bn)
{
	bignum_t *bn2 = ptr;

	if (size < (sizeof(bignum_t) + bn->size))
	{
		return NULL;
	}

	memcpy(bn2->words, bn->words, bn2->size);

	bn2->bits = bn->bits;
	bn2->sign = bn->sign;

	return bn2;
}

bignum_t *bignum_dup(bignum_t *bn)
{
	bignum_t *bn2 = bignum_new(bn->bits);

	if (bn2 == NULL)
	{
		return NULL;
	}

	memcpy(bn2->words, bn->words, bn2->size);

	bn2->bits = bn->bits;
	bn2->sign = bn->sign;

	return bn2;
}

uint32_t bignum_bitcount(bignum_t *bn)
{
	uint32_t count = bn->size / BIGNUM_WORD_SIZE;
	uint32_t i = count - 1;

	while (1)
	{
		if (bn->words[i] != 0)
		{
			// bsr returns index starting from 0.
			return (i * BIGNUM_BITS_PER_WORD) + bsr_64(bn->words[i]) + 1;
		}

		// All words of bn are zero.
		if (i == 0)
		{
			return 0;
		}

		--i;
	}
}

void bignum_zero(bignum_t *bn)
{
	// Zero the words and reset the struct.
	memset(bn->words, 0, bn->size);

	bn->bits = 0;
	bn->sign = 1;
}

void bignum_set(bignum_t *bn, bn_word_t value)
{
	bn->words[0] = value;
}
