/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>

static void basecase_multiply(uint64_t *r, uint64_t *a, uint64_t *b, uint32_t count)
{
	uint64_t temp = 0;
	uint64_t carry = 0;
	uint64_t high = 0;
	uint64_t low = 0;

	uint32_t *a32 = (uint32_t *)a;
	uint32_t *b32 = (uint32_t *)b;
	uint32_t *r32 = (uint32_t *)r;

	count *= 2;

	// Iterations go from r32[0 ... 2*count - 2]
	for (uint32_t i = 0; i < count; ++i)
	{
		for (uint32_t j = 0; j < count; ++j)
		{
			// Multiply 2 32-bit words to form a 64 bit product.
			// The high part is the carry for the next multiplication
			// The low part is added with the carry from previous multiplication to r32.
			temp = (uint64_t)a32[j] * (uint64_t)b32[i];
			high = temp >> 32;
			low = temp & 0xFFFFFFFF;

			low += r32[i + j] + carry;
			r32[i + j] = (uint32_t)(low & 0xFFFFFFFF);

			high += low >> 32;
			carry = high;
		}
	}

	// Last 32-bit word.
	r32[2 * count - 1] = (uint32_t)(carry & 0xFFFFFFFF);
}
