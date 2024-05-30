/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <rotate.h>
#include <sha.h>

// See NIST FIPS 202 : SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions

#define THETA_STEP_1(C, A, X) C[X] = A[X + 0 * 5] ^ A[X + 1 * 5] ^ A[X + 2 * 5] ^ A[X + 3 * 5] ^ A[X + 4 * 5];
#define THETA_STEP_2(D, C, X) D[X] = C[((5 + X) - 1) % 5] ^ ROTL_64(C[(X + 1) % 5], 1);
#define THETA_STEP_3(A, X, Y) A[X + 5 * Y] = A[X + 5 * Y] ^ D[X];

static inline void theta(uint64_t A[25])
{
	uint64_t C[5], D[5];

	// C[x,z] = A[x, 0, z] ^ A[x, 1, z] ^ A[x, 2, z] ^ A[x, 3, z] ^ A[x, 4, z]
	THETA_STEP_1(C, A, 0);
	THETA_STEP_1(C, A, 1);
	THETA_STEP_1(C, A, 2);
	THETA_STEP_1(C, A, 3);
	THETA_STEP_1(C, A, 4);

	// D[x,z] = C[(x-1) mod 5, z] ^ C[(x+1) mod 5, (z – 1) mod 64]
	THETA_STEP_2(D, C, 0);
	THETA_STEP_2(D, C, 1);
	THETA_STEP_2(D, C, 2);
	THETA_STEP_2(D, C, 3);
	THETA_STEP_2(D, C, 4);

	// A'[x, y, z] = A[x, y, z] ^ D[x, z]
	THETA_STEP_3(A, 0, 0);
	THETA_STEP_3(A, 0, 1);
	THETA_STEP_3(A, 0, 2);
	THETA_STEP_3(A, 0, 3);
	THETA_STEP_3(A, 0, 4);

	THETA_STEP_3(A, 1, 0);
	THETA_STEP_3(A, 1, 1);
	THETA_STEP_3(A, 1, 2);
	THETA_STEP_3(A, 1, 3);
	THETA_STEP_3(A, 1, 4);

	THETA_STEP_3(A, 2, 0);
	THETA_STEP_3(A, 2, 1);
	THETA_STEP_3(A, 2, 2);
	THETA_STEP_3(A, 2, 3);
	THETA_STEP_3(A, 2, 4);

	THETA_STEP_3(A, 3, 0);
	THETA_STEP_3(A, 3, 1);
	THETA_STEP_3(A, 3, 2);
	THETA_STEP_3(A, 3, 3);
	THETA_STEP_3(A, 3, 4);

	THETA_STEP_3(A, 4, 0);
	THETA_STEP_3(A, 4, 1);
	THETA_STEP_3(A, 4, 2);
	THETA_STEP_3(A, 4, 3);
	THETA_STEP_3(A, 4, 4);
}

static const uint8_t RHO_ROTATES[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

#define RHO_STEP(A, R) A[R] = ROTL_64(A[R], RHO_ROTATES[R]);

static inline void rho(uint64_t A[25])
{
	// A'[x, y, z] = A[x, y, (z – (t + 1)(t + 2)/2) mod 64]
	// (x,y) = (y, (2x + 3y) mod 5)
	RHO_STEP(A, 0);
	RHO_STEP(A, 1);
	RHO_STEP(A, 2);
	RHO_STEP(A, 3);

	RHO_STEP(A, 4);
	RHO_STEP(A, 5);
	RHO_STEP(A, 6);
	RHO_STEP(A, 7);
	RHO_STEP(A, 8);
	RHO_STEP(A, 9);
	RHO_STEP(A, 10);
	RHO_STEP(A, 11);
	RHO_STEP(A, 12);
	RHO_STEP(A, 13);
	RHO_STEP(A, 14);
	RHO_STEP(A, 15);
	RHO_STEP(A, 16);
	RHO_STEP(A, 17);
	RHO_STEP(A, 18);
	RHO_STEP(A, 19);
	RHO_STEP(A, 20);
	RHO_STEP(A, 21);
	RHO_STEP(A, 22);
	RHO_STEP(A, 23);
	RHO_STEP(A, 24);
}

#define PI_STEP(A, T, X, Y) A[X + 5 * Y] = T[(X + 3 * Y) % 5 + X * 5];

static inline void pi(uint64_t A[25])
{
	uint64_t T[25];

	memcpy(T, A, KECCAK1600_BLOCK_SIZE);

	// A'[x, y, z]= A[(x + 3y) mod 5, x, z]
	PI_STEP(A, T, 0, 0);
	PI_STEP(A, T, 0, 1);
	PI_STEP(A, T, 0, 2);
	PI_STEP(A, T, 0, 3);
	PI_STEP(A, T, 0, 4);

	PI_STEP(A, T, 1, 0);
	PI_STEP(A, T, 1, 1);
	PI_STEP(A, T, 1, 2);
	PI_STEP(A, T, 1, 3);
	PI_STEP(A, T, 1, 4);

	PI_STEP(A, T, 2, 0);
	PI_STEP(A, T, 2, 1);
	PI_STEP(A, T, 2, 2);
	PI_STEP(A, T, 2, 3);
	PI_STEP(A, T, 2, 4);

	PI_STEP(A, T, 3, 0);
	PI_STEP(A, T, 3, 1);
	PI_STEP(A, T, 3, 2);
	PI_STEP(A, T, 3, 3);
	PI_STEP(A, T, 3, 4);

	PI_STEP(A, T, 4, 0);
	PI_STEP(A, T, 4, 1);
	PI_STEP(A, T, 4, 2);
	PI_STEP(A, T, 4, 3);
	PI_STEP(A, T, 4, 4);
}

#define CHI_STEP(A, T, X, Y) A[X + 5 * Y] = T[X + 5 * Y] ^ (~T[(X + 1) % 5 + 5 * Y] & T[(X + 2) % 5 + 5 * Y]);

static inline void chi(uint64_t A[25])
{
	uint64_t T[25];

	memcpy(T, A, KECCAK1600_BLOCK_SIZE);

	// A'[x, y, z] = A[x, y, z] ^ ((A[(x+1) mod 5, y, z] ^ 1) & A[(x+2) mod 5, y, z]).
	CHI_STEP(A, T, 0, 0);
	CHI_STEP(A, T, 0, 1);
	CHI_STEP(A, T, 0, 2);
	CHI_STEP(A, T, 0, 3);
	CHI_STEP(A, T, 0, 4);

	CHI_STEP(A, T, 1, 0);
	CHI_STEP(A, T, 1, 1);
	CHI_STEP(A, T, 1, 2);
	CHI_STEP(A, T, 1, 3);
	CHI_STEP(A, T, 1, 4);

	CHI_STEP(A, T, 2, 0);
	CHI_STEP(A, T, 2, 1);
	CHI_STEP(A, T, 2, 2);
	CHI_STEP(A, T, 2, 3);
	CHI_STEP(A, T, 2, 4);

	CHI_STEP(A, T, 3, 0);
	CHI_STEP(A, T, 3, 1);
	CHI_STEP(A, T, 3, 2);
	CHI_STEP(A, T, 3, 3);
	CHI_STEP(A, T, 3, 4);

	CHI_STEP(A, T, 4, 0);
	CHI_STEP(A, T, 4, 1);
	CHI_STEP(A, T, 4, 2);
	CHI_STEP(A, T, 4, 3);
	CHI_STEP(A, T, 4, 4);
}

static const uint64_t IOTA_CONSTANTS[24] = {
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

static inline void iota(uint64_t A[25], uint32_t round)
{
	A[0] ^= IOTA_CONSTANTS[round];
}

#define KECCAK_ROUND(I, A) \
	{                      \
		theta(A);          \
		rho(A);            \
		pi(A);             \
		chi(A);            \
		iota(A, I);        \
	}

void keccak1600(uint64_t A[25])
{
	// Rounds 1 - 24
	KECCAK_ROUND(0, A);
	KECCAK_ROUND(1, A);
	KECCAK_ROUND(2, A);
	KECCAK_ROUND(3, A);
	KECCAK_ROUND(4, A);
	KECCAK_ROUND(5, A);
	KECCAK_ROUND(6, A);
	KECCAK_ROUND(7, A);
	KECCAK_ROUND(8, A);
	KECCAK_ROUND(9, A);
	KECCAK_ROUND(10, A);
	KECCAK_ROUND(11, A);
	KECCAK_ROUND(12, A);
	KECCAK_ROUND(13, A);
	KECCAK_ROUND(14, A);
	KECCAK_ROUND(15, A);
	KECCAK_ROUND(16, A);
	KECCAK_ROUND(17, A);
	KECCAK_ROUND(18, A);
	KECCAK_ROUND(19, A);
	KECCAK_ROUND(20, A);
	KECCAK_ROUND(21, A);
	KECCAK_ROUND(22, A);
	KECCAK_ROUND(23, A);
}

void sha3_hash_block(sha3_ctx *ctx)
{
	for (uint32_t i = 0; i < KECCAK1600_BLOCK_SIZE; ++i)
	{
		ctx->block[i] ^= ctx->internal[i];
	}

	keccak1600((uint64_t *)ctx->block);
}

static inline sha3_ctx *sha3_init_checked(void *ptr, sha3_type type)
{
	sha3_ctx *ctx = (sha3_ctx *)ptr;

	memset(ctx, 0, sizeof(sha3_ctx));

	switch (type)
	{
	case SHA3_224:
		ctx->hash_size = SHA3_224_HASH_SIZE;
		ctx->block_size = SHA3_224_BLOCK_SIZE;
		break;
	case SHA3_256:
		ctx->hash_size = SHA3_256_HASH_SIZE;
		ctx->block_size = SHA3_256_BLOCK_SIZE;
		break;
	case SHA3_384:
		ctx->hash_size = SHA3_384_HASH_SIZE;
		ctx->block_size = SHA3_384_BLOCK_SIZE;
		break;
	case SHA3_512:
		ctx->hash_size = SHA3_512_HASH_SIZE;
		ctx->block_size = SHA3_512_BLOCK_SIZE;
		break;
	}

	return ctx;
}

sha3_ctx *sha3_init(void *ptr, size_t size, sha3_type type)
{
	if (size < sizeof(sha3_ctx))
	{
		return NULL;
	}

	if (type != SHA3_224 && type != SHA3_256 && type != SHA3_384 && type != SHA3_512)
	{
		return NULL;
	}

	return sha3_init_checked(ptr, type);
}

sha3_ctx *sha3_new(sha3_type type)
{
	sha3_ctx *ctx = NULL;

	if (type != SHA3_224 && type != SHA3_256 && type != SHA3_384 && type != SHA3_512)
	{
		return NULL;
	}

	ctx = (sha3_ctx *)malloc(sizeof(sha3_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return sha3_init_checked(ctx, type);
}

void sha3_delete(sha3_ctx *ctx)
{
	free(ctx);
}

void sha3_reset(sha3_ctx *ctx)
{
	uint32_t hash_size = ctx->hash_size;
	uint32_t block_size = ctx->block_size;

	memset(ctx, 0, sizeof(sha3_ctx));

	ctx->hash_size = hash_size;
	ctx->block_size = block_size;
}

void sha3_update(sha3_ctx *ctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t remaining = 0;
	uint64_t unhashed = ctx->message_size % ctx->block_size;
	byte_t *pdata = (byte_t *)data;

	// First process the previous data if any.
	if (unhashed != 0)
	{
		uint64_t spill = ctx->block_size - unhashed;

		if (size < spill)
		{
			memcpy(&ctx->internal[unhashed], pdata, size);
			ctx->message_size += size;

			// Nothing to do.
			return;
		}

		memcpy(&ctx->internal[unhashed], pdata, spill);

		ctx->message_size += spill;
		pos += spill;

		sha3_hash_block(ctx);
	}

	while (pos + ctx->block_size <= size)
	{
		memcpy(ctx->internal, pdata + pos, ctx->block_size);
		sha3_hash_block(ctx);

		ctx->message_size += ctx->block_size;
		pos += ctx->block_size;
	}

	// Copy the remaining data to the internal buffer.
	remaining = size - pos;

	if (remaining > 0)
	{
		ctx->message_size += remaining;

		memcpy(&ctx->internal[0], pdata + pos, remaining);
	}
}

int32_t sha3_final(sha3_ctx *ctx, void *buffer, size_t size)
{
	uint64_t unhashed = ctx->message_size % ctx->block_size;

	if (size < ctx->hash_size)
	{
		return -1;
	}

	// First zero the internal buffer after unhashed input
	memset(&ctx->internal[unhashed], 0, ctx->block_size - unhashed);

	// Append '011' as bitstring. (i.e 00000110)
	ctx->internal[unhashed++] |= 0x06;

	// Most significant bit set to 1.
	ctx->internal[ctx->block_size - 1] |= 0x80;

	// Final hash
	sha3_hash_block(ctx);

	// Copy to buffer
	memcpy(buffer, ctx->block, ctx->hash_size);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha3_ctx));

	return 0;
}

static sha3_ctx *sha3_init_checked_ex(void *ptr, size_t hash_size, size_t block_size)
{
	sha3_ctx *ctx = (sha3_ctx *)ptr;

	memset(ctx, 0, sizeof(sha3_ctx));

	ctx->hash_size = hash_size;
	ctx->block_size = block_size;

	return ctx;
}

static void sha3_common_hash(size_t hash_size, size_t block_size, void *data, size_t message_size, byte_t *buffer)
{
	sha3_ctx ctx;

	// Initialize the context.
	sha3_init_checked_ex(&ctx, hash_size, block_size);

	// Hash the data.
	sha3_update(&ctx, data, message_size);

	// Output the hash
	sha3_final(&ctx, buffer, ctx.hash_size);
}

// SHA3-224

sha3_224_ctx *sha3_224_init(void *ptr, size_t size)
{
	if (size < sizeof(sha3_ctx))
	{
		return NULL;
	}

	return sha3_init_checked_ex(ptr, SHA3_224_HASH_SIZE, SHA3_224_BLOCK_SIZE);
}

sha3_224_ctx *sha3_224_new(void)
{
	sha3_ctx *ctx = (sha3_ctx *)malloc(sizeof(sha3_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return sha3_init_checked_ex(ctx, SHA3_224_HASH_SIZE, SHA3_224_BLOCK_SIZE);
}

void sha3_224_delete(sha3_224_ctx *ctx)
{
	free(ctx);
}

void sha3_224_reset(sha3_224_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha3_ctx));

	ctx->hash_size = SHA3_224_HASH_SIZE;
	ctx->block_size = SHA3_224_BLOCK_SIZE;
}

void sha3_224_update(sha3_224_ctx *ctx, void *data, size_t size)
{
	sha3_update(ctx, data, size);
}

void sha3_224_final(sha3_224_ctx *ctx, byte_t buffer[SHA3_224_HASH_SIZE])
{
	sha3_final(ctx, buffer, ctx->hash_size);
}

void sha3_224_hash(void *data, size_t size, byte_t buffer[SHA3_224_HASH_SIZE])
{
	sha3_common_hash(SHA3_224_HASH_SIZE, SHA3_224_BLOCK_SIZE, data, size, buffer);
}

// SHA3-256

sha3_256_ctx *sha3_256_init(void *ptr, size_t size)
{
	if (size < sizeof(sha3_ctx))
	{
		return NULL;
	}

	return sha3_init_checked_ex(ptr, SHA3_256_HASH_SIZE, SHA3_256_BLOCK_SIZE);
}

sha3_256_ctx *sha3_256_new(void)
{
	sha3_ctx *ctx = (sha3_ctx *)malloc(sizeof(sha3_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return sha3_init_checked_ex(ctx, SHA3_256_HASH_SIZE, SHA3_256_BLOCK_SIZE);
}

void sha3_256_delete(sha3_256_ctx *ctx)
{
	free(ctx);
}

void sha3_256_reset(sha3_256_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha3_ctx));

	ctx->hash_size = SHA3_256_HASH_SIZE;
	ctx->block_size = SHA3_256_BLOCK_SIZE;
}

void sha3_256_update(sha3_256_ctx *ctx, void *data, size_t size)
{
	sha3_update(ctx, data, size);
}

void sha3_256_final(sha3_256_ctx *ctx, byte_t buffer[SHA3_256_HASH_SIZE])
{
	sha3_final(ctx, buffer, ctx->hash_size);
}

void sha3_256_hash(void *data, size_t size, byte_t buffer[SHA3_256_HASH_SIZE])
{
	sha3_common_hash(SHA3_256_HASH_SIZE, SHA3_256_BLOCK_SIZE, data, size, buffer);
}

// SHA3-384

sha3_384_ctx *sha3_384_init(void *ptr, size_t size)
{
	if (size < sizeof(sha3_ctx))
	{
		return NULL;
	}

	return sha3_init_checked_ex(ptr, SHA3_384_HASH_SIZE, SHA3_384_BLOCK_SIZE);
}

sha3_384_ctx *sha3_384_new(void)
{
	sha3_ctx *ctx = (sha3_ctx *)malloc(sizeof(sha3_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return sha3_init_checked_ex(ctx, SHA3_384_HASH_SIZE, SHA3_384_BLOCK_SIZE);
}

void sha3_384_delete(sha3_384_ctx *ctx)
{
	free(ctx);
}

void sha3_384_reset(sha3_384_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha3_ctx));

	ctx->hash_size = SHA3_384_HASH_SIZE;
	ctx->block_size = SHA3_384_BLOCK_SIZE;
}

void sha3_384_update(sha3_384_ctx *ctx, void *data, size_t size)
{
	sha3_update(ctx, data, size);
}

void sha3_384_final(sha3_384_ctx *ctx, byte_t buffer[SHA3_384_HASH_SIZE])
{
	sha3_final(ctx, buffer, ctx->hash_size);
}

void sha3_384_hash(void *data, size_t size, byte_t buffer[SHA3_384_HASH_SIZE])
{
	sha3_common_hash(SHA3_384_HASH_SIZE, SHA3_384_BLOCK_SIZE, data, size, buffer);
}

// SHA3-512

sha3_512_ctx *sha3_512_init(void *ptr, size_t size)
{
	if (size < sizeof(sha3_ctx))
	{
		return NULL;
	}

	return sha3_init_checked_ex(ptr, SHA3_512_HASH_SIZE, SHA3_512_BLOCK_SIZE);
}

sha3_512_ctx *sha3_512_new(void)
{
	sha3_ctx *ctx = (sha3_ctx *)malloc(sizeof(sha3_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return sha3_init_checked_ex(ctx, SHA3_512_HASH_SIZE, SHA3_512_BLOCK_SIZE);
}

void sha3_512_delete(sha3_512_ctx *ctx)
{
	free(ctx);
}

void sha3_512_reset(sha3_512_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha3_ctx));

	ctx->hash_size = SHA3_512_HASH_SIZE;
	ctx->block_size = SHA3_512_BLOCK_SIZE;
}

void sha3_512_update(sha3_512_ctx *ctx, void *data, size_t size)
{
	sha3_update(ctx, data, size);
}

void sha3_512_final(sha3_512_ctx *ctx, byte_t buffer[SHA3_512_HASH_SIZE])
{
	sha3_final(ctx, buffer, ctx->hash_size);
}

void sha3_512_hash(void *data, size_t size, byte_t buffer[SHA3_512_HASH_SIZE])
{
	sha3_common_hash(SHA3_512_HASH_SIZE, SHA3_512_BLOCK_SIZE, data, size, buffer);
}
