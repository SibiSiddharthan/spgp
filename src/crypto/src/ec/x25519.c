/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <string.h>
#include <xor.h>

#define X25519_OCTET_SIZE 32
#define X25519_WORD_COUNT 4

#define AND8(R, A, B)                                                 \
	{                                                                 \
		*((uint64_t *)(R)) = *((uint64_t *)(A)) & *((uint64_t *)(B)); \
	}

#define AND32(R, A, B)                                                 \
	{                                                                  \
		AND8(R, A, B);                                                 \
		AND8(PTR_OFFSET(R, 8), PTR_OFFSET(A, 8), PTR_OFFSET(B, 8));    \
		AND8(PTR_OFFSET(R, 16), PTR_OFFSET(A, 16), PTR_OFFSET(B, 16)); \
		AND8(PTR_OFFSET(R, 32), PTR_OFFSET(A, 32), PTR_OFFSET(B, 32)); \
	}

#define CSWAP(SWAP, X, Y)                                                   \
	{                                                                       \
		bn_word_t mask[X25519_WORD_COUNT] = {0};                            \
		bn_word_t temp[X25519_WORD_COUNT] = {0};                            \
                                                                            \
		bignum_sub_words(mask, mask, (bn_word_t *)SWAP, X25519_WORD_COUNT); \
		XOR32(temp, X, Y);                                                  \
		AND32(mask, X, Y);                                                  \
                                                                            \
		XOR32(X, X, mask);                                                  \
		XOR32(Y, Y, mask);                                                  \
	}

void x25519_decode_scalar(byte_t k[X25519_OCTET_SIZE])
{
	// Set the 3 least significant bits of first byte to 0
	k[0] &= 248;

	// Set the most significant bit of the last byte to 0
	k[31] &= 127;

	// Set the second most significant bit of the last byte to 1
	k[31] |= 64;
}

void x25519_point_multiply(byte_t v[X25519_OCTET_SIZE], byte_t u[X25519_OCTET_SIZE], byte_t k[X25519_OCTET_SIZE])
{
	const uint32_t a24 = 121665;

	byte_t swap[X25519_OCTET_SIZE] = {0};

	bn_word_t x1[X25519_WORD_COUNT * 2] = {0};
	bn_word_t x2[X25519_WORD_COUNT * 2] = {0};
	bn_word_t z1[X25519_WORD_COUNT * 2] = {0};
	bn_word_t z2[X25519_WORD_COUNT * 2] = {0};

	bn_word_t a[X25519_WORD_COUNT] = {0};
	bn_word_t b[X25519_WORD_COUNT] = {0};
	bn_word_t c[X25519_WORD_COUNT] = {0};
	bn_word_t d[X25519_WORD_COUNT] = {0};
	bn_word_t e[X25519_WORD_COUNT] = {0};

	bn_word_t aa[X25519_WORD_COUNT * 2] = {0};
	bn_word_t bb[X25519_WORD_COUNT * 2] = {0};
	bn_word_t da[X25519_WORD_COUNT * 2] = {0};
	bn_word_t cb[X25519_WORD_COUNT * 2] = {0};

	bn_word_t t1[X25519_WORD_COUNT * 2] = {0};
	bn_word_t t2[X25519_WORD_COUNT * 2] = {0};

	byte_t kt = 0;
	byte_t t = 0;

	x1[0] = 1;
	z2[0] = 1;

	memcpy(x2, u, X25519_OCTET_SIZE);

	x25519_decode_scalar(k);

	for (uint32_t i = 0; i < 255; ++i)
	{
		t = 255 - (i + 1);
		kt = (k[t / 8] >> (t & 8)) & 0x1;

		swap[0] ^= kt;

		CSWAP(swap, x1, x2);
		CSWAP(swap, z1, z2);

		swap[0] = kt;

		memset(aa, 0, X25519_WORD_COUNT * 2);
		memset(bb, 0, X25519_WORD_COUNT * 2);
		memset(da, 0, X25519_WORD_COUNT * 2);
		memset(cb, 0, X25519_WORD_COUNT * 2);
		memset(t1, 0, X25519_WORD_COUNT * 2);
		memset(t2, 0, X25519_WORD_COUNT * 2);

		bignum_add_words(a, x1, z1, X25519_WORD_COUNT);
		bignum_sqr_words(aa, a, X25519_WORD_COUNT);
		bignum_sub_words(b, x1, z1, X25519_WORD_COUNT);
		bignum_sqr_words(bb, b, X25519_WORD_COUNT);
		bignum_sub_words(e, aa, bb, X25519_WORD_COUNT);
		bignum_add_words(c, x2, z2, X25519_WORD_COUNT);
		bignum_sub_words(d, x2, z2, X25519_WORD_COUNT);
		bignum_mul_words(da, d, a, X25519_WORD_COUNT, X25519_WORD_COUNT);
		bignum_mul_words(cb, c, b, X25519_WORD_COUNT, X25519_WORD_COUNT);

		bignum_add_words(t1, da, cb, X25519_WORD_COUNT);
		bignum_sqr_words(x2, t1, X25519_WORD_COUNT);

		bignum_sub_words(t1, da, cb, X25519_WORD_COUNT);
		bignum_sqr_words(t2, t1, X25519_WORD_COUNT);
		bignum_mul_words(z2, x1, t2, X25519_WORD_COUNT, X25519_WORD_COUNT);

		bignum_mul_words(x1, aa, bb, X25519_WORD_COUNT, X25519_WORD_COUNT);

		memset(t1, 0, X25519_OCTET_SIZE * 2);
		bignum_mul32((uint32_t *)t1, (uint32_t *)e, X25519_WORD_COUNT * 2, a24);
		bignum_add_words(t2, aa, t1, X25519_WORD_COUNT);
		bignum_mul_words(z1, e, t2, X25519_WORD_COUNT, X25519_WORD_COUNT);
	}

	CSWAP(swap, x1, x2);
	CSWAP(swap, z1, z2);

	bignum_mul_words((bn_word_t *)v, x1, z1, X25519_WORD_COUNT, X25519_WORD_COUNT);
}
