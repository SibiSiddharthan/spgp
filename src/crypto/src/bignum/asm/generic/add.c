/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <bignum.h>

uint8_t bignum_add_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count)
{
	uint8_t carry = 0;
	bn_word_t temp_a = 0;
	bn_word_t temp_b = 0;

	for (uint32_t pos = 0; pos < count; ++pos)
	{
		temp_a = *a;
		temp_b = *b;

		// Add the previous carry.
		*r = temp_a + carry; // carry -> 0|1
		carry = (*r < temp_a); // Next carry
		*r += temp_b;
		carry |= (*r < temp_b); // Next carry

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
