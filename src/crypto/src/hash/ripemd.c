/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <rotate.h>
#include <ripemd.h>

// See RIPEMD-160: A Strengthened Version of RIPEMD

// Initialization vectors
static const uint32_t H0 = 0x67452301;
static const uint32_t H1 = 0xEFCDAB89;
static const uint32_t H2 = 0x98BADCFE;
static const uint32_t H3 = 0x10325476;
static const uint32_t H4 = 0xC3D2E1F0;

// RIPEMD-160 Constants
static const uint32_t KA_0 = 0x00000000; // Rounds 1 - 16
static const uint32_t KA_1 = 0x5A827999; // Rounds 17 - 32
static const uint32_t KA_2 = 0x6ED9EBA1; // Rounds 33 - 48
static const uint32_t KA_3 = 0x8F1BBCDC; // Rounds 49 - 64
static const uint32_t KA_4 = 0xA953FD4E; // Rounds 65 - 80

static const uint32_t KB_0 = 0x50A28BE6; // Rounds 1 - 16
static const uint32_t KB_1 = 0x5C4DD124; // Rounds 17 - 32
static const uint32_t KB_2 = 0x6D703EF3; // Rounds 33 - 48
static const uint32_t KB_3 = 0x7A6D76E9; // Rounds 49 - 64
static const uint32_t KB_4 = 0x00000000; // Rounds 65 - 80

// clang-format off
// Message word selection
static const uint8_t RA[80] = 
{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3,  8, 11, 6, 15, 13
};

static const uint8_t RB[80] = 
{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

// Rotations
static const uint8_t SA[80] = 
{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

static const uint8_t SB[80] = 
{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};
// clang-format on

// Auxillary functions
#define F1(x, y, z) ((x) ^ (y) ^ (z))            // Rounds 1 - 16
#define F2(x, y, z) (((x) & (y)) | (~(x) & (z))) // Rounds 17 - 32
#define F3(x, y, z) (((x) | ~(y)) ^ (z))         // Rounds 33 - 48
#define F4(x, y, z) (((x) & (z)) | ((y) & ~(z))) // Rounds 49 - 64
#define F5(x, y, z) ((x) ^ ((y) | ~(z)))         // Rounds 65 - 80

#define RIPEMD160_ROUND_STEP(F, W, J, S, K, T, A, B, C, D, E) \
	{                                                         \
		T = ROTL_32(A + F(B, C, D) + W[J] + K, S) + E;        \
		A = E;                                                \
		E = D;                                                \
		D = ROTL_32(C, 10);                                   \
		C = B;                                                \
		B = T;                                                \
	}

#define RIPEMD160_ROUND(I, X, Y, W, KA, KB, T, A1, B1, C1, D1, E1, A2, B2, C2, D2, E2) \
	{                                                                                  \
		RIPEMD160_ROUND_STEP(X, W, RA[I], SA[I], KA, T, A1, B1, C1, D1, E1);           \
		RIPEMD160_ROUND_STEP(Y, W, RB[I], SB[I], KB, T, A2, B2, C2, D2, E2);           \
	}

static void ripemd160_hash_block(ripemd160_ctx *ctx, byte_t block[RIPEMD160_BLOCK_SIZE])
{
	uint32_t a1, b1, c1, d1, e1;
	uint32_t a2, b2, c2, d2, e2;
	uint32_t t;
	uint32_t *words = (uint32_t *)block;

	a1 = ctx->h0;
	b1 = ctx->h1;
	c1 = ctx->h2;
	d1 = ctx->h3;
	e1 = ctx->h4;

	a2 = ctx->h0;
	b2 = ctx->h1;
	c2 = ctx->h2;
	d2 = ctx->h3;
	e2 = ctx->h4;

	// Rounds 1 - 16
	RIPEMD160_ROUND(0, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(1, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(2, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(3, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(4, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(5, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(6, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(7, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(8, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(9, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(10, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(11, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(12, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(13, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(14, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(15, F1, F5, words, KA_0, KB_0, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);

	// Rounds 17 - 32
	RIPEMD160_ROUND(16, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(17, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(18, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(19, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(20, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(21, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(22, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(23, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(24, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(25, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(26, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(27, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(28, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(29, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(30, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(31, F2, F4, words, KA_1, KB_1, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);

	// Rounds 33 - 48
	RIPEMD160_ROUND(32, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(33, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(34, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(35, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(36, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(37, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(38, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(39, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(40, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(41, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(42, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(43, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(44, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(45, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(46, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(47, F3, F3, words, KA_2, KB_2, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);

	// Rounds 49 - 64
	RIPEMD160_ROUND(48, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(49, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(50, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(51, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(52, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(53, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(54, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(55, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(56, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(57, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(58, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(59, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(60, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(61, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(62, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(63, F4, F2, words, KA_3, KB_3, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);

	// Rounds 65 - 80
	RIPEMD160_ROUND(64, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(65, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(66, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(67, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(68, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(69, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(70, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(71, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(72, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(73, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(74, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(75, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(76, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(77, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(78, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);
	RIPEMD160_ROUND(79, F5, F1, words, KA_4, KB_4, t, a1, b1, c1, d1, e1, a2, b2, c2, d2, e2);

	t = ctx->h1 + c1 + d2;
	ctx->h1 = ctx->h2 + d1 + e2;
	ctx->h2 = ctx->h3 + e1 + a2;
	ctx->h3 = ctx->h4 + a1 + b2;
	ctx->h4 = ctx->h0 + b1 + c2;
	ctx->h0 = t;
}

static inline ripemd160_ctx *ripemd160_init_checked(void *ptr)
{
	ripemd160_ctx *ctx = (ripemd160_ctx *)ptr;

	memset(ctx, 0, sizeof(ripemd160_ctx));

	ctx->h0 = H0;
	ctx->h1 = H1;
	ctx->h2 = H2;
	ctx->h3 = H3;
	ctx->h4 = H4;

	return ctx;
}

ripemd160_ctx *ripemd160_init(void *ptr, size_t size)
{
	if (size < sizeof(ripemd160_ctx))
	{
		return NULL;
	}

	return ripemd160_init_checked(ptr);
}

ripemd160_ctx *ripemd160_new(void)
{
	ripemd160_ctx *ctx = (ripemd160_ctx *)malloc(sizeof(ripemd160_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return ripemd160_init_checked(ctx);
}

void ripemd160_delete(ripemd160_ctx *ctx)
{
	free(ctx);
}

void ripemd160_reset(ripemd160_ctx *ctx)
{
	ripemd160_init_checked(ctx);
}

void ripemd160_update(ripemd160_ctx *ctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t remaining = 0;
	uint64_t unhashed = ctx->size % RIPEMD160_BLOCK_SIZE;
	byte_t *pdata = (byte_t *)data;

	// First process the previous data if any.
	if (unhashed != 0)
	{
		uint64_t spill = RIPEMD160_BLOCK_SIZE - unhashed;

		if (size < spill)
		{
			memcpy(&ctx->internal[unhashed], pdata, size);
			ctx->size += size;

			// Nothing to do.
			return;
		}

		memcpy(&ctx->internal[unhashed], pdata, spill);

		ctx->size += spill;
		pos += spill;

		ripemd160_hash_block(ctx, ctx->internal);
	}

	while (pos + RIPEMD160_BLOCK_SIZE <= size)
	{
		memcpy(ctx->internal, pdata + pos, RIPEMD160_BLOCK_SIZE);
		ripemd160_hash_block(ctx, ctx->internal);

		ctx->size += RIPEMD160_BLOCK_SIZE;
		pos += RIPEMD160_BLOCK_SIZE;
	}

	// Copy the remaining data to the internal buffer.
	remaining = size - pos;

	if (remaining > 0)
	{
		ctx->size += remaining;

		memcpy(&ctx->internal[0], pdata + pos, remaining);
	}
}

void ripemd160_final(ripemd160_ctx *ctx, byte_t buffer[RIPEMD160_HASH_SIZE])
{
	uint64_t bits = ctx->size * 8;
	uint64_t zero_padding = ((64 + 56) - ((ctx->size + 1) % 64)) % 64; // (l+1+k)mod64 = 56mod64
	uint64_t total_padding = 0;
	byte_t padding[128] = {0};

	// First byte.
	padding[0] = 0x80;
	total_padding += 1;

	// Zero padding
	total_padding += zero_padding;

	// Append message length (bits) in Little Endian order.
	memcpy(&padding[total_padding], &bits, sizeof(uint64_t));
	total_padding += 8;

	// Final Hash.
	ripemd160_update(ctx, padding, total_padding);

	// Copy the hash to the buffer, {h0,h1,h2,h3,h4} in Little Endian Order.
	memcpy(buffer, &ctx->h0, RIPEMD160_HASH_SIZE);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(ripemd160_ctx));
}

void ripemd160_hash(void *data, size_t size, byte_t buffer[RIPEMD160_HASH_SIZE])
{
	ripemd160_ctx ctx;

	// Initialize the context.
	ripemd160_init_checked(&ctx);

	// Hash the data.
	ripemd160_update(&ctx, data, size);

	// Output the hash
	ripemd160_final(&ctx, buffer);
}
