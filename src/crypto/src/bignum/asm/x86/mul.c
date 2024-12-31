/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <intrin.h>

void bignum_mul_words(uint64_t *r, uint64_t *a, uint64_t *b, uint32_t a_words, uint32_t b_words)
{
	uint64_t high = 0;
	uint64_t low = 0;
	uint8_t carry = 0;

	// Iterations go from r32[0 ... 2*count - 2]
	for (uint32_t i = 0; i < b_words; ++i)
	{
		for (uint32_t j = 0; j < a_words; ++j)
		{
			// Multiply 2 64-bit words to form a 128 bit product.
			low = _umul128(a[j], b[i], &high);

			// Perform the carries.
			carry = _addcarry_u64(carry, r[i + j], low, &r[i + j]);
			carry = _addcarry_u64(carry, r[i + j + 1], high, &r[i + j + 1]);
		}
	}

	// NOTE: There won't be any carries here (i.e carry = 0).
}
