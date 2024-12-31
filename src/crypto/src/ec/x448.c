/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <string.h>
#include <xor.h>

#define X448_OCTET_SIZE 56
#define X448_WORD_COUNT 7

static inline void and8(void *r, void *a, void *b, size_t n)
{
	uint64_t *r64 = r;
	uint64_t *a64 = a;
	uint64_t *b64 = b;

	while (n != 0)
	{
		*r64 = *a64 & *b64;

		r64++;
		a64++;
		b64++;
		n -= 8;
	}
}

#define AND8_N(R, A, B, N) and8(R, A, B, N)

#define CSWAP(SWAP, X, Y)                                                 \
	{                                                                     \
		bn_word_t mask[X448_WORD_COUNT] = {0};                            \
		bn_word_t temp[X448_WORD_COUNT] = {0};                            \
                                                                          \
		bignum_sub_words(mask, mask, (bn_word_t *)SWAP, X448_WORD_COUNT); \
		XOR8_N(temp, X, Y, X448_WORD_COUNT);                              \
		AND8_N(mask, X, Y, X448_WORD_COUNT);                              \
                                                                          \
		XOR8_N(X, X, mask, X448_WORD_COUNT);                              \
		XOR8_N(Y, Y, mask, X448_WORD_COUNT);                              \
	}

void x448_decode_scalar(byte_t k[X448_OCTET_SIZE])
{
	// Set the 2 least significant bits of first byte to 0
	k[0] &= 252;

	// Set the most significant bit of the last byte to 1
	k[55] |= 128;
}

void x448_point_multiply(byte_t v[X448_OCTET_SIZE], byte_t u[X448_OCTET_SIZE], byte_t k[X448_OCTET_SIZE])
{
	const uint32_t a24 = 39081;

	byte_t swap[X448_OCTET_SIZE] = {0};

	bn_word_t x1[X448_WORD_COUNT * 2] = {0};
	bn_word_t x2[X448_WORD_COUNT * 2] = {0};
	bn_word_t z1[X448_WORD_COUNT * 2] = {0};
	bn_word_t z2[X448_WORD_COUNT * 2] = {0};

	bn_word_t a[X448_WORD_COUNT] = {0};
	bn_word_t b[X448_WORD_COUNT] = {0};
	bn_word_t c[X448_WORD_COUNT] = {0};
	bn_word_t d[X448_WORD_COUNT] = {0};
	bn_word_t e[X448_WORD_COUNT] = {0};

	bn_word_t aa[X448_WORD_COUNT * 2] = {0};
	bn_word_t bb[X448_WORD_COUNT * 2] = {0};
	bn_word_t da[X448_WORD_COUNT * 2] = {0};
	bn_word_t cb[X448_WORD_COUNT * 2] = {0};

	bn_word_t t1[X448_WORD_COUNT * 2] = {0};
	bn_word_t t2[X448_WORD_COUNT * 2] = {0};

	byte_t kt = 0;
	byte_t t = 0;

	x1[0] = 1;
	z2[0] = 1;

	memcpy(x2, u, X448_OCTET_SIZE);

	x448_decode_scalar(k);

	for (uint32_t i = 0; i < 255; ++i)
	{
		t = 255 - (i + 1);
		kt = (k[t / 8] >> (t & 8)) & 0x1;

		swap[0] ^= kt;

		CSWAP(swap, x1, x2);
		CSWAP(swap, z1, z2);

		swap[0] = kt;

		memset(aa, 0, X448_WORD_COUNT * 2);
		memset(bb, 0, X448_WORD_COUNT * 2);
		memset(da, 0, X448_WORD_COUNT * 2);
		memset(cb, 0, X448_WORD_COUNT * 2);
		memset(t1, 0, X448_WORD_COUNT * 2);
		memset(t2, 0, X448_WORD_COUNT * 2);

		bignum_add_words(a, x1, z1, X448_WORD_COUNT);
		bignum_sqr_words(aa, a, X448_WORD_COUNT);
		bignum_sub_words(b, x1, z1, X448_WORD_COUNT);
		bignum_sqr_words(bb, b, X448_WORD_COUNT);
		bignum_sub_words(e, aa, bb, X448_WORD_COUNT);
		bignum_add_words(c, x2, z2, X448_WORD_COUNT);
		bignum_sub_words(d, x2, z2, X448_WORD_COUNT);
		bignum_mul_words(da, d, a, X448_WORD_COUNT, X448_WORD_COUNT);
		bignum_mul_words(cb, c, b, X448_WORD_COUNT, X448_WORD_COUNT);

		bignum_add_words(t1, da, cb, X448_WORD_COUNT);
		bignum_sqr_words(x2, t1, X448_WORD_COUNT);

		bignum_sub_words(t1, da, cb, X448_WORD_COUNT);
		bignum_sqr_words(t2, t1, X448_WORD_COUNT);
		bignum_mul_words(z2, x1, t2, X448_WORD_COUNT, X448_WORD_COUNT);

		bignum_mul_words(x1, aa, bb, X448_WORD_COUNT, X448_WORD_COUNT);

		memset(t1, 0, X448_OCTET_SIZE * 2);
		bignum_mul32((uint32_t *)t1, (uint32_t *)e, X448_WORD_COUNT * 2, a24);
		bignum_add_words(t2, aa, t1, X448_WORD_COUNT);
		bignum_mul_words(z1, e, t2, X448_WORD_COUNT, X448_WORD_COUNT);
	}

	CSWAP(swap, x1, x2);
	CSWAP(swap, z1, z2);

	bignum_mul_words((bn_word_t *)v, x1, z1, X448_WORD_COUNT, X448_WORD_COUNT);
}