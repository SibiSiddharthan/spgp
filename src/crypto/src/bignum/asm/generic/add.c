/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>

uint8_t bignum_add_words(uint64_t *r, uint64_t *a, uint64_t *b, uint32_t count)
{
	uint8_t carry = 0;

	for (uint32_t pos = 0; pos < count; ++pos)
	{
		// We only need to check one of the values if there is a carry.
		// *r < *a, *r < *b
		*r = *a + *b + carry;
		carry = (*r < *a); 

		a++;
		b++;
		r++;
	}

	return carry;
}
