/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include <bitscan.h>
#include <minmax.h>
#include <round.h>

#include <bignum-internal.h>

bignum_t *bignum_init_checked(void *ptr, size_t bn_size, uint32_t bits)
{
	bignum_t *bn = (bignum_t *)ptr;

	memset(bn, 0, bn_size);

	// Atleast one word will be allocatted.
	bn->bits = 0;
	bn->sign = 1;
	bn->size = CEIL_DIV(bits, 8);
	bn->words = (uint64_t *)((byte_t *)bn + sizeof(bignum_t));

	return bn;
}

bignum_t *bignum_init(void *ptr, size_t size, uint32_t bits)
{
	bignum_t *bn = (bignum_t *)ptr;
	size_t required_size = sizeof(bignum_t);

	bits = ROUND_UP(MAX(bits, 1), BIGNUM_BITS_PER_WORD);
	required_size += bits / 8;

	if (size < required_size)
	{
		return NULL;
	}

	return bignum_init_checked(bn, required_size, bits);
}

bignum_t *bignum_new(uint32_t bits)
{
	bignum_t *bn = NULL;
	size_t size = sizeof(bignum_t);

	bits = ROUND_UP(MAX(bits, 1), BIGNUM_BITS_PER_WORD);
	size += bits / 8;

	bn = (bignum_t *)malloc(size);

	if (bn == NULL)
	{
		return NULL;
	}

	return bignum_init_checked(bn, size, bits);
}

void bignum_delete(bignum_t *bn)
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

bignum_t *bignum_copy(bignum_t *dst_bn, bignum_t *src_bn)
{
	size_t copy_size = BIGNUM_WORD_COUNT(src_bn) * BIGNUM_WORD_SIZE;

	if (dst_bn->size < copy_size)
	{
		return NULL;
	}

	memset(dst_bn->words, 0, dst_bn->size);
	memcpy(dst_bn->words, src_bn->words, copy_size);

	dst_bn->bits = src_bn->bits;
	dst_bn->sign = src_bn->sign;

	return dst_bn;
}

bignum_t *bignum_dup(bignum_ctx *bctx, bignum_t *bn)
{
	bignum_t *bn2 = NULL;

	if (bctx != NULL)
	{
		bn2 = bignum_ctx_allocate_bignum(bctx, bn->bits);
	}
	else
	{
		bn2 = bignum_new(bn->bits);
	}

	if (bn2 == NULL)
	{
		return NULL;
	}

	memcpy(bn2->words, bn->words, bn->size);

	bn2->bits = bn->bits;
	bn2->sign = bn->sign;

	return bn2;
}

bignum_t *bignum_resize(bignum_t *bn, uint32_t bits)
{
	size_t new_size = 0;
	void *ptr = NULL;

	bits = ROUND_UP(MAX(bits, 1), BIGNUM_BITS_PER_WORD);
	new_size = bits / 8;

	// Create a new bignum_t.
	if (bn == NULL)
	{
		return bignum_new(bits);
	}

	// Bignum is already big enough just return.
	if ((bn->size * 8) >= bits)
	{
		return bn;
	}

	if (bn->flags & BIGNUM_FLAG_NO_RESIZE)
	{
		return NULL;
	}

	// Expand it.
	ptr = malloc(new_size);
	memset(ptr, 0, new_size);

	if (ptr == NULL)
	{
		return NULL;
	}

	// Copy old stuff
	memcpy(ptr, bn->words, CEIL_DIV(bn->bits, 8));

	// Free old words if it was allocated by another malloc.
	if (bn->resize)
	{
		free(bn->words);
	}

	bn->size = new_size;
	bn->words = ptr;
	bn->resize = 1;

	return bn;
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

uint32_t bignum_ctz(bignum_t *bn)
{
	uint32_t count = bn->size / BIGNUM_WORD_SIZE;

	for (uint32_t i = 0; i < count; ++i)
	{
		if (bn->words[i] == 0)
		{
			continue;
		}

		return (i * BIGNUM_BITS_PER_WORD) + bsf_64(bn->words[i]);
	}

	return count * BIGNUM_BITS_PER_WORD;
}

void bignum_zero(bignum_t *bn)
{
	// Zero the words and reset the struct.
	memset(bn->words, 0, bn->size);

	bn->bits = 0;
	bn->sign = 1;
}

void bignum_one(bignum_t *bn)
{
	// Zero the words and reset the struct.
	memset(bn->words, 0, bn->size);

	bn->words[0] = 1;
	bn->bits = 1;
	bn->sign = 1;
}

void bignum_set_word(bignum_t *bn, bn_word_t value)
{
	// Zero the words.
	memset(bn->words, 0, bn->size);

	// Set the least significant word.
	bn->words[0] = value;
	bn->bits = bsr_64(value);
}

void bignum_set_sign(bignum_t *bn, int8_t sign)
{
	bn->sign = sign >= 0 ? 1 : -1;
}

void bignum_set_flags(bignum_t *bn, int16_t flags)
{
	bn->flags = flags & BIGNUM_FLAG_MASK;
}
