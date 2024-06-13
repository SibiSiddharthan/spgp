/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <bignum.h>

// If a > b ->  1
// If a < b -> -1
// If a = b ->  0
int32_t bignum_cmp_words(bn_word_t *a, bn_word_t *b, uint32_t count)
{
	bn_word_t result = 0;

	// Start from MSB
	a += (count - 1);
	b += (count - 1);

	for (int32_t pos = 0; pos < count; ++pos)
	{
		result = *a - *b;

		if (result == 0)
		{
			continue;
		}

		// a > b
		if (result <= *a)
		{
			return 1;
		}
		// a < b
		else
		{
			return -1;
		}

		--a;
		--b;
	}

	// a = b
	return 0;
}
