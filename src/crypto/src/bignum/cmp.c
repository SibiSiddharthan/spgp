/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>
#include <round.h>

// If a > b ->  1
// If a < b -> -1
// If a = b ->  0
int32_t bignum_cmp_words(bn_word_t *a, bn_word_t *b, uint32_t count);

int32_t bignum_cmp(bignum_t *a, bignum_t *b)
{

	int32_t modifier = 1;

	if (a->sign == b->sign)
	{
		// If a is negative, flip the modifier.
		if (a->sign < 0)
		{
			modifier = -1;
		}

		return modifier * bignum_cmp_abs(a, b);
	}
	else
	{
		// a is positive, b is negative
		if (a->sign >= 0)
		{
			return 1;
		}
		// a is negative, b is positive
		else
		{
			return -1;
		}
	}
}

int32_t bignum_cmp_abs(bignum_t *a, bignum_t *b)
{
	if (a->bits > b->bits)
	{
		return 1;
	}
	else if (a->bits < b->bits)
	{
		return -1;
	}
	else // (a->bits == b->bits)
	{
		return bignum_cmp_words(a->words, b->words, CEIL_DIV(a->bits, BIGNUM_BITS_PER_WORD));
	}
}
