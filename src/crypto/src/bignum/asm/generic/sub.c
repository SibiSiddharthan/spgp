/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>

uint8_t bignum_sub_words(uint64_t *r, uint64_t *a, uint64_t *b, uint32_t count)
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
