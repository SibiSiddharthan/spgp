/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <bignum.h>

void bignum_increment(bn_word_t *r, uint32_t count);

uint8_t bignum_sub_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count)
{
	uint8_t borrow = 0;

	for (uint32_t pos = 0; pos < count; ++pos)
	{
		*r = *a - *b - borrow;
		borrow = (*r > *a);

		a++;
		b++;
		r++;
	}

	return borrow;
}

void bignum_2complement(bn_word_t *r, uint32_t count)
{
	bn_word_t *t = r;

	// Invert
	for (uint32_t pos = 0; pos < count; ++pos)
	{
		*t = ~(*t);
		t++;
	}

	// Add one
	bignum_increment(r, count);
}
