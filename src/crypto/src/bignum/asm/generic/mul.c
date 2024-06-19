/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <bignum.h>

static void basecase_multiply(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t a_words, uint32_t b_words, uint32_t r_words)
{
	bn_word_t temp = 0;
	bn_word_t carry = 0;
	bn_word_t high = 0;
	bn_word_t low = 0;

	uint32_t *a32 = (uint32_t *)a;
	uint32_t *b32 = (uint32_t *)b;
	uint32_t *r32 = (uint32_t *)r;

	// Iterations go from r32[0 ... 2*a_words + 2*b_words - 2]
	for (uint32_t i = 0; i < a_words * 2; ++i)
	{
		carry = 0;

		for (uint32_t j = 0; j < b_words * 2; ++j)
		{
			// Skip iterations where zero words would be accessed.
			if ((i + j) >= (r_words * 2))
			{
				continue;
			}

			// Multiply 2 32-bit words to form a 64 bit product.
			// The high part is the carry for the next multiplication
			// The low part is added with the carry from previous multiplication to r32.
			temp = (bn_word_t)a32[i] * (bn_word_t)b32[j];
			high = temp >> 32;
			low = temp & 0xFFFFFFFF;

			low += r32[i + j] + carry;
			r32[i + j] = (uint32_t)(low & 0xFFFFFFFF);

			high += (low >> 32);
			carry = high;
		}

		if ((i + (2 * b_words)) >= (r_words * 2))
		{
			continue;
		}

		r32[i + (2 * b_words)] = (uint32_t)(carry & 0xFFFFFFFF);
	}
}

void bignum_mul_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t a_words, uint32_t b_words, uint32_t r_words)
{
	return basecase_multiply(r, a, b, a_words, b_words, r_words);
}
