/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <rotate.h>
#include <blake2.h>

// See RFC 7693 : The BLAKE2 Cryptographic Hash and Message Authentication Code

// clang-format off
// Initialization vectors
static const uint64_t BLAKE2B_IV[8] = 
{
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

static const uint32_t BLAKE2S_IV[8] = 
{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// Message Schedule table
static const uint8_t SIGMA[12][16] = 
{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
};

// clang-format on

#define B2B_G(V, A, B, C, D, SX, SY)     \
	{                                    \
		V[A] = V[A] + V[B] + SX;         \
		V[D] = ROTR_64(V[D] ^ V[A], 32); \
		V[C] = V[C] + V[D];              \
		V[B] = ROTR_64(V[B] ^ V[C], 24); \
		V[A] = V[A] + V[B] + SY;         \
		V[D] = ROTR_64(V[D] ^ V[A], 16); \
		V[C] = V[C] + V[D];              \
		V[B] = ROTR_64(V[B] ^ V[C], 63); \
	}

#define B2S_G(V, A, B, C, D, SX, SY)     \
	{                                    \
		V[A] = V[A] + V[B] + SX;         \
		V[D] = ROTR_32(V[D] ^ V[A], 16); \
		V[C] = V[C] + V[D];              \
		V[B] = ROTR_32(V[B] ^ V[C], 12); \
		V[A] = V[A] + V[B] + SY;         \
		V[D] = ROTR_32(V[D] ^ V[A], 8);  \
		V[C] = V[C] + V[D];              \
		V[B] = ROTR_32(V[B] ^ V[C], 7);  \
	}

#define BLAKE2B_ROUND(I, V, W)                                    \
	{                                                             \
		B2B_G(V, 0, 4, 8, 12, W[SIGMA[I][0]], W[SIGMA[I][1]]);    \
		B2B_G(V, 1, 5, 9, 13, W[SIGMA[I][2]], W[SIGMA[I][3]]);    \
		B2B_G(V, 2, 6, 10, 14, W[SIGMA[I][4]], W[SIGMA[I][5]]);   \
		B2B_G(V, 3, 7, 11, 15, W[SIGMA[I][6]], W[SIGMA[I][7]]);   \
		B2B_G(V, 0, 5, 10, 15, W[SIGMA[I][8]], W[SIGMA[I][9]]);   \
		B2B_G(V, 1, 6, 11, 12, W[SIGMA[I][10]], W[SIGMA[I][11]]); \
		B2B_G(V, 2, 7, 8, 13, W[SIGMA[I][12]], W[SIGMA[I][13]]);  \
		B2B_G(V, 3, 4, 9, 14, W[SIGMA[I][14]], W[SIGMA[I][15]]);  \
	}

#define BLAKE2S_ROUND(I, V, W)                                    \
	{                                                             \
		B2S_G(V, 0, 4, 8, 12, W[SIGMA[I][0]], W[SIGMA[I][1]]);    \
		B2S_G(V, 1, 5, 9, 13, W[SIGMA[I][2]], W[SIGMA[I][3]]);    \
		B2S_G(V, 2, 6, 10, 14, W[SIGMA[I][4]], W[SIGMA[I][5]]);   \
		B2S_G(V, 3, 7, 11, 15, W[SIGMA[I][6]], W[SIGMA[I][7]]);   \
		B2S_G(V, 0, 5, 10, 15, W[SIGMA[I][8]], W[SIGMA[I][9]]);   \
		B2S_G(V, 1, 6, 11, 12, W[SIGMA[I][10]], W[SIGMA[I][11]]); \
		B2S_G(V, 2, 7, 8, 13, W[SIGMA[I][12]], W[SIGMA[I][13]]);  \
		B2S_G(V, 3, 4, 9, 14, W[SIGMA[I][14]], W[SIGMA[I][15]]);  \
	}

static void blake2b_hash_block(blake2b_ctx *ctx, byte_t block[BLAKE2B_BLOCK_SIZE], bool final)
{
	uint64_t work[16];
	uint64_t *words = (uint64_t *)block;

	memcpy(&work[0], ctx->state, sizeof(uint64_t) * 8);
	memcpy(&work[8], BLAKE2B_IV, sizeof(uint64_t) * 8);

	work[12] ^= ctx->size[0]; // low 64 bits
	work[13] ^= ctx->size[1]; // high 64 bits

	if (final)
	{
		work[14] = ~work[14];
	}

	// Rounds 1 - 12
	BLAKE2B_ROUND(0, work, words);
	BLAKE2B_ROUND(1, work, words);
	BLAKE2B_ROUND(2, work, words);
	BLAKE2B_ROUND(3, work, words);
	BLAKE2B_ROUND(4, work, words);
	BLAKE2B_ROUND(5, work, words);
	BLAKE2B_ROUND(6, work, words);
	BLAKE2B_ROUND(7, work, words);
	BLAKE2B_ROUND(8, work, words);
	BLAKE2B_ROUND(9, work, words);
	BLAKE2B_ROUND(10, work, words);
	BLAKE2B_ROUND(11, work, words);

	for (uint32_t i = 0; i < 8; ++i)
	{
		ctx->state[i] ^= work[i] ^ work[i + 8];
	}
}

static void blake2s_hash_block(blake2s_ctx *ctx, byte_t block[BLAKE2S_BLOCK_SIZE], bool final)
{
	uint32_t work[16];
	uint32_t *words = (uint64_t *)block;
	uint32_t *size = (uint32_t *)&ctx->size;

	memcpy(&work[0], ctx->state, sizeof(uint32_t) * 8);
	memcpy(&work[8], BLAKE2S_IV, sizeof(uint32_t) * 8);

	work[12] ^= size[0]; // low 32 bits
	work[13] ^= size[1]; // high 32 bits

	if (final)
	{
		work[14] = ~work[14];
	}

	// Rounds 1 - 10
	BLAKE2S_ROUND(0, work, words);
	BLAKE2S_ROUND(1, work, words);
	BLAKE2S_ROUND(2, work, words);
	BLAKE2S_ROUND(3, work, words);
	BLAKE2S_ROUND(4, work, words);
	BLAKE2S_ROUND(5, work, words);
	BLAKE2S_ROUND(6, work, words);
	BLAKE2S_ROUND(7, work, words);
	BLAKE2S_ROUND(8, work, words);
	BLAKE2S_ROUND(9, work, words);

	for (uint32_t i = 0; i < 8; ++i)
	{
		ctx->state[i] ^= work[i] ^ work[i + 8];
	}
}

blake2b_ctx *blake2b_init(uint32_t hash_size, void *key, uint32_t key_size)
{
	blake2b_ctx *ctx = NULL;

	if (!(hash_size <= BLAKE2B_MAX_HASH_SIZE && hash_size >= 1))
	{
		return NULL;
	}

	if (!(key_size <= BLAKE2B_MAX_KEY_SIZE && key_size >= 0))
	{
		return NULL;
	}

	ctx = malloc(sizeof(blake2b_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	memset(ctx, 0, sizeof(blake2b_ctx));

	ctx->hash_size = hash_size;
	ctx->key_size = key_size;

	memcpy(ctx->state, BLAKE2B_IV, sizeof(uint64_t) * 8);

	// XOR with parameter block.
	ctx->state[0] ^= 0x01010000 | (key_size << 8) | hash_size;

	// Keyed hashing.
	if (key_size > 0)
	{
		memcpy(ctx->internal, key, key_size);
		blake2b_hash_block(ctx, ctx->internal, false);
		ctx->size[0] += BLAKE2B_BLOCK_SIZE;
	}

	return ctx;
}

void blake2b_free(blake2b_ctx *ctx)
{
	free(ctx);
}

void blake2b_update(blake2b_ctx *ctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t remaining = 0;
	uint64_t unhashed = ctx->size[0] % BLAKE2B_BLOCK_SIZE;
	byte_t *pdata = (byte_t *)data;

	// First process the previous data if any.
	if (unhashed != 0)
	{
		uint64_t spill = BLAKE2B_BLOCK_SIZE - unhashed;

		memcpy(&ctx->internal[unhashed], pdata, spill);

		ctx->size[1] += (ctx->size[0] + spill < ctx->size[0]);
		ctx->size[0] += spill;
		pos += spill;

		blake2b_hash_block(ctx, ctx->internal, false);
	}

	while (pos + BLAKE2B_BLOCK_SIZE <= size)
	{
		blake2b_hash_block(ctx, (pdata + pos), false);

		ctx->size[1] += (ctx->size[0] + BLAKE2B_BLOCK_SIZE < ctx->size[0]);
		ctx->size[0] += BLAKE2B_BLOCK_SIZE;
		pos += BLAKE2B_BLOCK_SIZE;
	}

	// Copy the remaining data to the internal buffer.
	remaining = size - pos;

	if (remaining > 0)
	{
		ctx->size[1] += (ctx->size[0] + remaining < ctx->size[0]);
		ctx->size[0] += remaining;

		memcpy(&ctx->internal[0], pdata + pos, remaining);
	}
}

int32_t blake2b_final(blake2b_ctx *ctx, byte_t *buffer, size_t size)
{
	uint64_t unhashed = ctx->size[0] % BLAKE2B_BLOCK_SIZE;

	if (size < ctx->hash_size)
	{
		return -1;
	}

	// Zero padding
	memset(&ctx->internal[unhashed], 0, BLAKE2B_BLOCK_SIZE - unhashed);

	// Final hash
	blake2b_hash_block(ctx, ctx->internal, true);

	// Copy the hash to the buffer, {state[0..8]} in Little Endian Order.
	memcpy(buffer, ctx->state, ctx->hash_size);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(blake2b_ctx));

	return 0;
}

blake2s_ctx *blake2s_init(uint32_t hash_size, void *key, uint32_t key_size)
{
	blake2s_ctx *ctx = NULL;

	if (!(hash_size <= BLAKE2S_MAX_HASH_SIZE && hash_size >= 1))
	{
		return NULL;
	}

	if (!(key_size <= BLAKE2S_MAX_KEY_SIZE && key_size >= 0))
	{
		return NULL;
	}

	ctx = malloc(sizeof(blake2s_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	memset(ctx, 0, sizeof(blake2s_ctx));

	ctx->hash_size = hash_size;
	ctx->key_size = key_size;

	memcpy(ctx->state, BLAKE2S_IV, sizeof(uint32_t) * 8);

	// XOR with parameter block.
	ctx->state[0] ^= 0x01010000 | (key_size << 8) | hash_size;

	// Keyed hashing.
	if (key_size > 0)
	{
		memcpy(ctx->internal, key, key_size);
		blake2s_hash_block(ctx, ctx->internal, false);
		ctx->size += BLAKE2S_BLOCK_SIZE;
	}

	return ctx;
}

void blake2s_free(blake2s_ctx *ctx)
{
	free(ctx);
}

void blake2s_update(blake2s_ctx *ctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t remaining = 0;
	uint64_t unhashed = ctx->size % BLAKE2S_BLOCK_SIZE;
	byte_t *pdata = (byte_t *)data;

	// First process the previous data if any.
	if (unhashed != 0)
	{
		uint64_t spill = BLAKE2S_BLOCK_SIZE - unhashed;

		memcpy(&ctx->internal[unhashed], pdata, spill);

		ctx->size += spill;
		pos += spill;

		blake2s_hash_block(ctx, ctx->internal, false);
	}

	while (pos + BLAKE2S_BLOCK_SIZE <= size)
	{
		blake2s_hash_block(ctx, (pdata + pos), false);

		ctx->size += BLAKE2S_BLOCK_SIZE;
		pos += BLAKE2S_BLOCK_SIZE;
	}

	// Copy the remaining data to the internal buffer.
	remaining = size - pos;

	if (remaining > 0)
	{
		ctx->size += remaining;

		memcpy(&ctx->internal[0], pdata + pos, remaining);
	}
}

int32_t blake2s_final(blake2s_ctx *ctx, byte_t *buffer, size_t size)
{
	uint64_t unhashed = ctx->size % BLAKE2S_BLOCK_SIZE;

	if (size < ctx->hash_size)
	{
		return -1;
	}

	// Zero padding
	memset(&ctx->internal[unhashed], 0, BLAKE2S_BLOCK_SIZE - unhashed);

	// Final hash
	blake2s_hash_block(ctx, ctx->internal, true);

	// Copy the hash to the buffer, {state[0..8]} in Little Endian Order.
	memcpy(buffer, ctx->state, ctx->hash_size);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(blake2s_ctx));

	return 0;
}
