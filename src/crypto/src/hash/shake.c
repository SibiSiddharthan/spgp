/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <shake.h>

// From sha3.c
void keccak1600(uint64_t A[25]);
void sha3_hash_block(sha3_ctx *ctx);

static int32_t shake_common_final(sha3_ctx *ctx, byte_t *buffer, size_t size)
{
	uint64_t unhashed = ctx->message_size % ctx->block_size;
	uint64_t shake_length = 0;

	if (size < ctx->hash_size)
	{
		return -1;
	}

	// First zero the internal buffer after unhashed input
	memset(&ctx->internal[unhashed], 0, ctx->block_size - unhashed);

	// Append '11111' as bitstring. (i.e 00011111)
	ctx->internal[unhashed++] ^= 0x1F;

	// Most significant bit set to 1.
	ctx->internal[ctx->block_size - 1] ^= 0x80;

	// Final hash
	sha3_hash_block(ctx);

	// Extend output
	while (1)
	{
		if (shake_length + ctx->block_size <= ctx->hash_size)
		{
			memcpy(buffer + shake_length, ctx->block, ctx->block_size);
			shake_length += ctx->block_size;

			if (shake_length == ctx->hash_size)
			{
				// Last iteration
				break;
			}

			// Next hash
			keccak1600((uint64_t *)ctx->block);
		}
		else
		{
			// Last iteration
			memcpy(buffer + shake_length, ctx->block, ctx->hash_size - shake_length);
			break;
		}
	}

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha3_ctx));

	return 0;
}

static inline shake128_ctx *shake128_init_checked(void *ptr, uint32_t bits)
{
	shake128_ctx *ctx = (shake128_ctx *)ptr;

	memset(ctx, 0, sizeof(shake128_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = SHAKE128_BLOCK_SIZE;

	return ctx;
}

shake128_ctx *shake128_init(void *ptr, size_t size, uint32_t bits)
{
	if (size < sizeof(shake128_ctx))
	{
		return NULL;
	}

	return shake128_init_checked(ptr, bits);
}

shake128_ctx *shake128_new(uint32_t bits)
{
	shake128_ctx *ctx = (shake128_ctx *)malloc(sizeof(shake128_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return shake128_init_checked(ctx, bits);
}

void shake128_delete(shake128_ctx *ctx)
{
	free(ctx);
}

void shake128_update(shake128_ctx *ctx, void *data, size_t size)
{
	return sha3_update(ctx, data, size);
}

int32_t shake128_final(shake128_ctx *ctx, byte_t *buffer, size_t size)
{
	return shake_common_final(ctx, buffer, size);
}

static inline shake256_ctx *shake256_init_checked(void *ptr, uint32_t bits)
{
	shake256_ctx *ctx = (shake256_ctx *)ptr;

	memset(ctx, 0, sizeof(shake256_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = SHAKE256_BLOCK_SIZE;

	return ctx;
}

shake256_ctx *shake256_init(void *ptr, size_t size, uint32_t bits)
{
	if (size < sizeof(shake256_ctx))
	{
		return NULL;
	}

	return shake256_init_checked(ptr, bits);
}

shake256_ctx *shake256_new(uint32_t bits)
{
	shake256_ctx *ctx = (shake256_ctx *)malloc(sizeof(shake256_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return shake256_init_checked(ctx, bits);
}

void shake256_delete(shake256_ctx *ctx)
{
	free(ctx);
}

void shake256_update(shake256_ctx *ctx, void *data, size_t size)
{
	return sha3_update(ctx, data, size);
}

int32_t shake256_final(shake256_ctx *ctx, byte_t *buffer, size_t size)
{
	return shake_common_final(ctx, buffer, size);
}
