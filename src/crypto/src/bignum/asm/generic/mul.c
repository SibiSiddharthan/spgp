/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <bignum.h>

static void basecase_multiply(uint32_t *r32, uint32_t *a32, uint32_t *b32, uint32_t a32_words, uint32_t b32_words)
{
	bn_word_t temp = 0;
	bn_word_t carry = 0;
	bn_word_t high = 0;
	bn_word_t low = 0;

	// Iterations go from r32[0 ... a32_words + b32_words - 2]
	for (uint32_t i = 0; i < a32_words; ++i)
	{
		carry = 0;

		for (uint32_t j = 0; j < b32_words; ++j)
		{
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

		r32[i + b32_words] = (uint32_t)(carry & 0xFFFFFFFF);
	}
}

static void basecase_square(uint32_t *r32, uint32_t *a32, uint32_t a32_words)
{
	bn_word_t temp = 0;
	bn_word_t carry = 0;
	bn_word_t high = 0;
	bn_word_t low = 0;

	// Iterations go from r32[0 ... a32_words - 2]
	for (uint32_t i = 0; i < a32_words; ++i)
	{
		carry = 0;

		// Multiply 2 32-bit words to form a 64 bit product.
		// The high part is the carry for the next multiplication
		// The low part is added with the carry from previous multiplication to r32.

		// First iteration
		temp = (bn_word_t)a32[i] * (bn_word_t)a32[i];

		high = temp >> 32;
		low = temp & 0xFFFFFFFF;

		low += r32[i + i] + carry;
		r32[i + i] = (uint32_t)(low & 0xFFFFFFFF);

		high += (low >> 32);
		carry = high;

		for (uint32_t j = i + 1; j < a32_words; ++j)
		{
			temp = (bn_word_t)a32[i] * (bn_word_t)a32[j];

			// Prevent repeated multiplications.
			high = (temp >> 31);
			low = (temp << 1) & 0xFFFFFFFF;

			low += r32[i + j] + carry;
			r32[i + j] = (uint32_t)(low & 0xFFFFFFFF);

			high += (low >> 32);
			carry = high;
		}

		r32[i + a32_words] += (uint32_t)(carry & 0xFFFFFFFF);

		// The carry for 2*x*y. This can be greater than 0xFFFFFFFF.
		// NOTE: The last word won't be accessed here. (r32[2 * a32_words])
		if (carry > 0xFFFFFFFF)
		{
			r32[i + a32_words + 1] = carry >> 32;
		}
	}
}

void bignum_mul_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t a_words, uint32_t b_words)
{
	uint32_t *a32 = (uint32_t *)a;
	uint32_t *b32 = (uint32_t *)b;
	uint32_t *r32 = (uint32_t *)r;

	uint32_t a32_words = a_words * 2;
	uint32_t b32_words = b_words * 2;

	// Calculate the correct word count.
	if (a32[a32_words - 1] == 0)
	{
		--a32_words;
	}

	if (b32[b32_words - 1] == 0)
	{
		--b32_words;
	}

	return basecase_multiply(r32, a32, b32, a32_words, b32_words);
}

void bignum_mul32(uint32_t *r32, uint32_t *a32, uint32_t a32_words, uint32_t w)
{
	bn_word_t carry = 0;

	for (uint32_t i = 0; i < a32_words; ++i)
	{
		bn_word_t temp = (bn_word_t)a32[i] * w;
		bn_word_t high = temp >> 32;
		bn_word_t low = (temp & 0xFFFFFFFF) + carry;

		r32[i] = (uint32_t)(low & 0xFFFFFFFF);

		high += (low >> 32);
		carry = high;
	}

	r32[a32_words] = (uint32_t)(carry & 0xFFFFFFFF);
}

void bignum_sqr_words(bn_word_t *r, bn_word_t *a, uint32_t a_words)
{
	uint32_t *a32 = (uint32_t *)a;
	uint32_t *r32 = (uint32_t *)r;

	uint32_t a32_words = a_words * 2;

	// Calculate the correct word count.
	if (a32[a32_words - 1] == 0)
	{
		--a32_words;
	}

	return basecase_square(r32, a32, a32_words);
}
