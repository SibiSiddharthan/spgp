/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <shake.h>
#include <bitscan.h>

#include <stdlib.h>
#include <string.h>

// See NIST FIPS 202 : SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
// See NIST SP 800-185: SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash

// From sha3.c
void keccak1600(uint64_t A[25]);
void sha3_hash_block(sha3_ctx *ctx);
void sha3_update(sha3_ctx *ctx, void *data, size_t size);

static void XOF(sha3_ctx *ctx, byte_t *buffer, size_t output_size)
{
	uint64_t shake_size = 0;

	while (1)
	{
		if (shake_size + ctx->block_size <= output_size)
		{
			memcpy(buffer + shake_size, ctx->block, ctx->block_size);
			shake_size += ctx->block_size;

			if (shake_size == output_size)
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
			memcpy(buffer + shake_size, ctx->block, output_size - shake_size);
			break;
		}
	}

	return;
}

static void shake_common_final(sha3_ctx *ctx, void *buffer, size_t size)
{
	uint64_t unhashed = ctx->message_size % ctx->block_size;
	uint64_t output_size = 0;

	// If 0 bits was given during init, implies XOF.
	if (ctx->hash_size == 0)
	{
		output_size = size;
	}
	else
	{
		output_size = MIN(size, ctx->hash_size);
	}

	// First zero the internal buffer after unhashed input
	memset(&ctx->internal[unhashed], 0, ctx->block_size - unhashed);

	// Append '11111' as bitstring. (i.e 00011111)
	ctx->internal[unhashed++] |= 0x1F;

	// Most significant bit set to 1.
	ctx->internal[ctx->block_size - 1] |= 0x80;

	// Final hash
	sha3_hash_block(ctx);

	// Extend output
	XOF(ctx, buffer, output_size);

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

void shake128_final(shake128_ctx *ctx, void *buffer, size_t size)
{
	return shake_common_final(ctx, buffer, size);
}

void shake128_xof(void *data, size_t data_size, void *xof, size_t xof_size)
{
	shake128_ctx ctx;

	// Initialize the context.
	shake128_init_checked(&ctx, xof_size * 8);

	// Hash the data.
	shake128_update(&ctx, data, data_size);

	// Output the XOF.
	shake128_final(&ctx, xof, xof_size);
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

void shake256_final(shake256_ctx *ctx, void *buffer, size_t size)
{
	return shake_common_final(ctx, buffer, size);
}

void shake256_xof(void *data, size_t data_size, void *xof, size_t xof_size)
{
	shake256_ctx ctx;

	// Initialize the context.
	shake256_init_checked(&ctx, xof_size * 8);

	// Hash the data.
	shake256_update(&ctx, data, data_size);

	// Output the XOF.
	shake256_final(&ctx, xof, xof_size);
}

// Get the index of most significant non zero byte.
static inline uint8_t leading(uint64_t x)
{
	return (bsr_64(x) / 8) + 1;
}

// leading(x) || BE(x)
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

// BE(x) || leading(x)
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

void cshake_common_final(sha3_ctx *ctx, void *buffer, size_t size)
{
	uint64_t unhashed = ctx->message_size % ctx->block_size;
	uint64_t output_size = 0;

	// If 0 bits was given during init, implies XOF.
	if (ctx->hash_size == 0)
	{
		output_size = size;
	}
	else
	{
		output_size = MIN(size, ctx->hash_size);
	}

	// First zero the internal buffer after unhashed input
	memset(&ctx->internal[unhashed], 0, ctx->block_size - unhashed);

	// Append '001' as bitstring. (i.e 00000100)
	ctx->internal[unhashed++] |= 0x04;

	// Most significant bit set to 1.
	ctx->internal[ctx->block_size - 1] |= 0x80;

	// Final hash
	sha3_hash_block(ctx);

	// Extend output
	XOF(ctx, buffer, output_size);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha3_ctx));
}

sha3_ctx *cshake_init_common(sha3_ctx *ctx, void *name, size_t name_size, void *custom, size_t custom_size)
{
	byte_t pad[16] = {0};
	uint64_t pos = 0;
	uint64_t zero_pad = 0;

	// cSHAKE128(X, L, N, S) = KECCAK[256](bytepad(encode_string(N) || encode_string(S), 168) || X || 00, L)
	// cSHAKE256(X, L, N, S) = KECCAK[512](bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)

	// Expansion of (bytepad(encode_string(N) || encode_string(S), B))
	// left_encode(B) || left_encode(N.size) || N || left_encode(S.size) || S || padding

	pos = left_encode(ctx->block_size, pad);
	sha3_update(ctx, pad, pos);

	pos = left_encode(name_size * 8, pad); // bits
	sha3_update(ctx, pad, pos);

	if (name != NULL)
	{
		sha3_update(ctx, name, name_size);
	}

	pos = left_encode(custom_size * 8, pad); // bits
	sha3_update(ctx, pad, pos);

	if (custom != NULL)
	{
		sha3_update(ctx, custom, custom_size);
	}

	zero_pad = ctx->message_size % ctx->block_size;

	if (zero_pad > 0)
	{
		memset(&ctx->internal[zero_pad], 0, ctx->block_size - zero_pad);
	}

	// Hash the state
	sha3_hash_block(ctx);
	ctx->message_size = 0;

	return ctx;
}

static shake128_ctx *cshake128_init_checked(void *ptr, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size)
{
	shake128_ctx *ctx = (shake128_ctx *)ptr;

	// Same as shake128
	if (name == NULL && custom == NULL)
	{
		return shake128_init_checked(ptr, bits);
	}

	memset(ctx, 0, sizeof(shake128_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = SHAKE128_BLOCK_SIZE;

	return cshake_init_common(ctx, name, name_size, custom, custom_size);
}

shake128_ctx *cshake128_init(void *ptr, size_t size, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size)
{
	if (size < sizeof(shake128_ctx))
	{
		return NULL;
	}

	return cshake128_init_checked(ptr, bits, name, name_size, custom, custom_size);
}

shake128_ctx *cshake128_new(uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size)
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

void cshake128_reset(shake128_ctx *ctx, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size)
{
	cshake128_init_checked(ctx, bits, name, name_size, custom, custom_size);
}

void cshake128_update(shake128_ctx *ctx, void *data, size_t size)
{
	return sha3_update(ctx, data, size);
}

void cshake128_final(shake128_ctx *ctx, void *buffer, size_t size)
{
	return cshake_common_final(ctx, buffer, size);
}

static shake256_ctx *cshake256_init_checked(void *ptr, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size)
{
	shake256_ctx *ctx = (shake256_ctx *)ptr;

	// Same as shake256
	if (name == NULL && custom == NULL)
	{
		return shake256_init_checked(ptr, bits);
	}

	memset(ctx, 0, sizeof(shake256_ctx));

	ctx->hash_size = bits / 8;
	ctx->block_size = SHAKE256_BLOCK_SIZE;

	return cshake_init_common(ctx, name, name_size, custom, custom_size);
}

shake256_ctx *cshake256_init(void *ptr, size_t size, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size)
{
	if (size < sizeof(shake256_ctx))
	{
		return NULL;
	}

	return cshake256_init_checked(ptr, bits, name, name_size, custom, custom_size);
}

shake256_ctx *cshake256_new(uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size)
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

void cshake256_reset(shake256_ctx *ctx, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size)
{
	cshake256_init_checked(ctx, bits, name, name_size, custom, custom_size);
}

void cshake256_update(shake256_ctx *ctx, void *data, size_t size)
{
	return sha3_update(ctx, data, size);
}

void cshake256_final(shake256_ctx *ctx, void *buffer, size_t size)
{
	return cshake_common_final(ctx, buffer, size);
}
