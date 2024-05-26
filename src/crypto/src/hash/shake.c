/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <shake.h>

// See NIST FIPS 202 : SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
// See NIST SP 800-185: SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash

// From sha3.c
void keccak1600(uint64_t A[25]);
void sha3_hash_block(sha3_ctx *ctx);

static void shake_common_final(sha3_ctx *ctx, byte_t *buffer, size_t size)
{
	uint64_t unhashed = ctx->message_size % ctx->block_size;
	uint64_t shake_length = 0;

	// First zero the internal buffer after unhashed input
	memset(&ctx->internal[unhashed], 0, ctx->block_size - unhashed);

	// Append '11111' as bitstring. (i.e 00011111)
	ctx->internal[unhashed++] |= 0x1F;

	// Most significant bit set to 1.
	ctx->internal[ctx->block_size - 1] |= 0x80;

	// Final hash
	sha3_hash_block(ctx);

	// Extend output
	while (1)
	{
		if (shake_length + ctx->block_size <= size)
		{
			memcpy(buffer + shake_length, ctx->block, ctx->block_size);
			shake_length += ctx->block_size;

			if (shake_length == size)
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
			memcpy(buffer + shake_length, ctx->block, size - shake_length);
			break;
		}
	}

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha3_ctx));
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

void shake128_reset(shake128_ctx *ctx, uint32_t bits)
{
	memset(ctx, 0, sizeof(shake128_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = SHAKE128_BLOCK_SIZE;
}

void shake128_update(shake128_ctx *ctx, void *data, size_t size)
{
	return sha3_update(ctx, data, size);
}

void shake128_final(shake128_ctx *ctx, byte_t *buffer, size_t size)
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

void shake256_reset(shake256_ctx *ctx, uint32_t bits)
{
	memset(ctx, 0, sizeof(shake256_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = SHAKE256_BLOCK_SIZE;
}

void shake256_update(shake256_ctx *ctx, void *data, size_t size)
{
	return sha3_update(ctx, data, size);
}

void shake256_final(shake256_ctx *ctx, byte_t *buffer, size_t size)
{
	return shake_common_final(ctx, buffer, size);
}

static uint8_t leading(uint64_t x)
{
	byte_t *p = (byte_t *)&x;

	if (x == 0)
	{
		return 1;
	}

	for (uint8_t i = 7; i >= 0; ++i)
	{
		if (p[i] != 0)
		{
			return i + 1;
		}
	}

	return 1;
}

uint8_t left_encode(uint64_t x, byte_t *o)
{
	uint8_t p = 0;
	uint8_t n = leading(x);

	o[p++] = n;

	for (uint8_t i = 1; i <= n; ++i)
	{
		o[p++] = (x >> (8 * (n - i))) & 0xFF;
	}

	return p;
}

uint8_t right_encode(uint64_t x, byte_t *o)
{
	uint8_t p = 0;
	uint8_t n = leading(x);

	for (uint8_t i = 1; i <= n; ++i)
	{
		o[p++] = (x >> (8 * (n - i))) & 0xFF;
	}

	o[p++] = n;

	return p;
}

uint64_t bytepad(byte_t *str, size_t str_size, size_t padding, byte_t *output)
{
	uint64_t pos = 0;
	uint64_t pad_zero = 0;

	pos += left_encode(padding, output);

	memcpy(output + pos, str, str_size);
	pos += str_size;

	pad_zero = pos % padding;

	if (pad_zero > 0)
	{
		memset(output + pos, 0, pad_zero);
		pos += pad_zero;
	}

	return pos;
}

uint64_t encode_string(byte_t *str, size_t str_size, byte_t *output)
{
	uint64_t pos = 0;

	pos += left_encode(str_size, output);

	memcpy(output + pos, str, str_size);
	pos += str_size;

	return pos;
}

void cshake_common_final(sha3_ctx *ctx, byte_t *buffer, size_t size)
{
	uint64_t unhashed = ctx->message_size % ctx->block_size;
	uint64_t shake_length = 0;

	// First zero the internal buffer after unhashed input
	memset(&ctx->internal[unhashed], 0, ctx->block_size - unhashed);

	// Append '001' as bitstring. (i.e 00000100)
	ctx->internal[unhashed++] |= 0x04;

	// Most significant bit set to 1.
	ctx->internal[ctx->block_size - 1] |= 0x80;

	// Final hash
	sha3_hash_block(ctx);

	// Extend output
	while (1)
	{
		if (shake_length + ctx->block_size <= size)
		{
			memcpy(buffer + shake_length, ctx->block, ctx->block_size);
			shake_length += ctx->block_size;

			if (shake_length == size)
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
			memcpy(buffer + shake_length, ctx->block, size - shake_length);
			break;
		}
	}

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha3_ctx));
}

sha3_ctx *cshake_init_common(sha3_ctx *ctx, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size)
{
	byte_t pad[16] = {0};
	uint64_t pos = 0;
	uint64_t zero_pad = 0;

	pos = left_encode(ctx->block_size, pad);
	sha3_update(ctx, pad, pos);

	pos = left_encode(name_size, pad);
	sha3_update(ctx, pad, pos);

	if (name != NULL)
	{
		sha3_update(ctx, name, name_size);
	}

	pos = left_encode(custom_size, pad);
	sha3_update(ctx, pad, pos);

	if (custom != NULL)
	{
		sha3_update(ctx, custom, custom_size);
	}

	zero_pad = ctx->message_size % ctx->block_size;

	if (zero_pad > 0)
	{
		memset(&ctx->internal[zero_pad], 0, ctx->block_size - zero_pad);
		ctx->message_size += zero_pad;
	}

	return ctx;
}

static shake128_ctx *cshake128_init_checked(void *ptr, uint32_t bits, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size)
{
	shake128_ctx *ctx = (shake128_ctx *)ptr;

	if (name == NULL && custom == NULL)
	{
		return shake128_init_checked(ptr, bits);
	}

	memset(ctx, 0, sizeof(shake128_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = SHAKE128_BLOCK_SIZE;

	return cshake_init_common(ctx, name, name_size, custom, custom_size);
}

shake128_ctx *cshake128_init(void *ptr, size_t size, uint32_t bits, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size)
{
	if (size < sizeof(shake128_ctx))
	{
		return NULL;
	}

	return cshake128_init_checked(ptr, bits, name, name_size, custom, custom_size);
}

shake128_ctx *cshake128_new(uint32_t bits, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size)
{
	shake128_ctx *ctx = (shake128_ctx *)malloc(sizeof(shake128_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return cshake128_init_checked(ctx, bits, name, name_size, custom, custom_size);
}

void cshake128_delete(shake128_ctx *ctx)
{
	free(ctx);
}

void cshake128_reset(shake128_ctx *ctx, uint32_t bits, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size)
{
	cshake128_init_checked(ctx, bits, name, name_size, custom, custom_size);
}

void cshake128_update(shake128_ctx *ctx, void *data, size_t size)
{
	return sha3_update(ctx, data, size);
}

void cshake128_final(shake128_ctx *ctx, byte_t *buffer, size_t size)
{
	return cshake_common_final(ctx, buffer, size);
}

static shake256_ctx *cshake256_init_checked(void *ptr, uint32_t bits, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size)
{
	shake256_ctx *ctx = (shake256_ctx *)ptr;

	if (name == NULL && custom == NULL)
	{
		return shake256_init_checked(ptr, bits);
	}

	memset(ctx, 0, sizeof(shake256_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = SHAKE256_BLOCK_SIZE;

	return cshake_init_common(ctx, name, name_size, custom, custom_size);
}

shake256_ctx *cshake256_init(void *ptr, size_t size, uint32_t bits, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size)
{
	if (size < sizeof(shake256_ctx))
	{
		return NULL;
	}

	return cshake256_init_checked(ptr, bits, name, name_size, custom, custom_size);
}

shake256_ctx *cshake256_new(uint32_t bits, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size)
{
	shake256_ctx *ctx = (shake256_ctx *)malloc(sizeof(shake256_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return cshake256_init_checked(ctx, bits, name, name_size, custom, custom_size);
}

void cshake256_delete(shake256_ctx *ctx)
{
	free(ctx);
}

void cshake256_reset(shake256_ctx *ctx, uint32_t bits, byte_t *name, size_t name_size, byte_t *custom, size_t custom_size)
{
	cshake256_init_checked(ctx, bits, name, name_size, custom, custom_size);
}

void cshake256_update(shake256_ctx *ctx, void *data, size_t size)
{
	return sha3_update(ctx, data, size);
}

void cshake256_final(shake256_ctx *ctx, byte_t *buffer, size_t size)
{
	return cshake_common_final(ctx, buffer, size);
}
