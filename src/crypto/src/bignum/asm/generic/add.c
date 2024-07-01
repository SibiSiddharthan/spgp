/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <bignum.h>

uint8_t bignum_add_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count)
{
	uint8_t carry = 0;
	bn_word_t temp = 0;

	for (uint32_t pos = 0; pos < count; ++pos)
	{
		// We only need to check one of the values if there is a carry.
		// *r < *a, *r < *b
		temp = *a;
		*r = temp + *b + carry;
		carry = (*r < temp);

		a++;
		b++;
		r++;
	}

	return carry;
}

void bignum_increment(bn_word_t *r, uint32_t count)
{
	for (uint32_t pos = 0; pos < count; ++pos)
	{
		++(*r);

		// If there is no carry, return.
		if (*r != 0)
		{
			return;
		}

		r++;
	}
}
