/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <shake.h>
#include <kmac.h>

// See NIST SP 800-185: SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash

// From shake.c
uint8_t left_encode(uint64_t x, byte_t *o);
uint8_t right_encode(uint64_t x, byte_t *o);
sha3_ctx *cshake_init_common(sha3_ctx *ctx, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size);
void cshake_common_final(sha3_ctx *ctx, byte_t *buffer, size_t size);

static sha3_ctx *kmac_init_common(sha3_ctx *ctx, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size)
{
	byte_t pad[16] = {0};
	uint64_t pos = 0;
	uint64_t zero_pad = 0;

	ctx = cshake_init_common(ctx, (byte_t *)"KMAC", 4, custom, custom_size);

	pos = left_encode(ctx->block_size, pad);
	sha3_update(ctx, pad, pos);

	pos = left_encode(key_size, pad);
	sha3_update(ctx, pad, pos);

	if (key != NULL)
	{
		sha3_update(ctx, key, key_size);
	}

	zero_pad = ctx->message_size % ctx->block_size;

	if (zero_pad > 0)
	{
		memset(&ctx->internal[zero_pad], 0, ctx->block_size - zero_pad);
		ctx->message_size += zero_pad;
	}

	return ctx;
}

static void kmac_common_final(sha3_ctx *ctx, byte_t *buffer, size_t size)
{
	byte_t pad[16] = {0};
	byte_t pos = 0;

	pos = right_encode(ctx->hash_size * 8, pad);
	sha3_update(ctx, pad, pos);

	cshake_common_final(ctx, buffer, size);
}

kmac128_ctx *kmac128_init_checked(void *ptr, uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size)
{
	kmac128_ctx *ctx = (kmac128_ctx *)ptr;

	memset(ctx, 0, sizeof(kmac128_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = KMAC128_BLOCK_SIZE;

	return kmac_init_common(ctx, key, key_size, custom, custom_size);
}

kmac128_ctx *kmac128_init(void *ptr, size_t size, uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size)
{
	if (size < sizeof(kmac128_ctx))
	{
		return NULL;
	}

	return kmac128_init_checked(ptr, bits, key, key_size, custom, custom_size);
}

kmac128_ctx *kmac128_new(uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size)
{
	kmac128_ctx *ctx = (kmac128_ctx *)malloc(sizeof(kmac128_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return kmac128_init_checked(ctx, bits, key, key_size, custom, custom_size);
}

void kmac128_delete(kmac128_ctx *ctx)
{
	free(ctx);
}

void kmac128_reset(kmac128_ctx *ctx, uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size)
{
	kmac128_init_checked(ctx, bits, key, key_size, custom, custom_size);
}

void kmac128_update(kmac128_ctx *ctx, void *data, size_t size)
{
	sha3_update(ctx, data, size);
}

void kmac128_final(kmac128_ctx *ctx, byte_t *buffer, size_t size)
{
	return kmac_common_final(ctx, buffer, size);
}

kmac256_ctx *kmac256_init_checked(void *ptr, uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size)
{
	kmac256_ctx *ctx = (kmac256_ctx *)ptr;

	memset(ctx, 0, sizeof(kmac256_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = KMAC256_BLOCK_SIZE;

	return kmac_init_common(ctx, key, key_size, custom, custom_size);
}

kmac256_ctx *kmac256_init(void *ptr, size_t size, uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size)
{
	if (size < sizeof(kmac256_ctx))
	{
		return NULL;
	}

	return kmac256_init_checked(ptr, bits, key, key_size, custom, custom_size);
}

kmac256_ctx *kmac256_new(uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size)
{
	kmac256_ctx *ctx = (kmac256_ctx *)malloc(sizeof(kmac256_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return kmac256_init_checked(ctx, bits, key, key_size, custom, custom_size);
}

void kmac256_delete(kmac256_ctx *ctx)
{
	free(ctx);
}

void kmac256_reset(kmac256_ctx *ctx, uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size)
{
	kmac256_init_checked(ctx, bits, key, key_size, custom, custom_size);
}

void kmac256_update(kmac256_ctx *ctx, void *data, size_t size)
{
	sha3_update(ctx, data, size);
}

void kmac256_final(kmac256_ctx *ctx, byte_t *buffer, size_t size)
{
	return kmac_common_final(ctx, buffer, size);
}
