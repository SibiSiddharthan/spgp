/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <rotate.h>
#include <md5.h>

// See RFC 1321 : The MD5 Message-Digest Algorithm

// Initialization vectors
static const uint32_t A = 0x67452301;
static const uint32_t B = 0xEFCDAB89;
static const uint32_t C = 0x98BADCFE;
static const uint32_t D = 0x10325476;

// Sine table
// clang-format off
static const uint32_t T[64] = 
{
	0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
	0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
	0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
	0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
	0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
	0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
	0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
	0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,	0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};
// clang-format on

// Auxillary functions
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define ROUND_1(a, b, c, d, w, k, s, t) (a) = (b) + (ROTL_32(((a) + F(b, c, d) + w[k] + T[t - 1]), s))
#define ROUND_2(a, b, c, d, w, k, s, t) (a) = (b) + (ROTL_32(((a) + G(b, c, d) + w[k] + T[t - 1]), s))
#define ROUND_3(a, b, c, d, w, k, s, t) (a) = (b) + (ROTL_32(((a) + H(b, c, d) + w[k] + T[t - 1]), s))
#define ROUND_4(a, b, c, d, w, k, s, t) (a) = (b) + (ROTL_32(((a) + I(b, c, d) + w[k] + T[t - 1]), s))

static void md5_hash_block(md5_ctx *ctx, byte_t block[MD5_BLOCK_SIZE])
{
	uint32_t a, b, c, d;
	uint32_t *w = (uint32_t *)block;

	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;

	ROUND_1(a, b, c, d, w, 0, 7, 1);
	ROUND_1(d, a, b, c, w, 1, 12, 2);
	ROUND_1(c, d, a, b, w, 2, 17, 3);
	ROUND_1(b, c, d, a, w, 3, 22, 4);
	ROUND_1(a, b, c, d, w, 4, 7, 5);
	ROUND_1(d, a, b, c, w, 5, 12, 6);
	ROUND_1(c, d, a, b, w, 6, 17, 7);
	ROUND_1(b, c, d, a, w, 7, 22, 8);
	ROUND_1(a, b, c, d, w, 8, 7, 9);
	ROUND_1(d, a, b, c, w, 9, 12, 10);
	ROUND_1(c, d, a, b, w, 10, 17, 11);
	ROUND_1(b, c, d, a, w, 11, 22, 12);
	ROUND_1(a, b, c, d, w, 12, 7, 13);
	ROUND_1(d, a, b, c, w, 13, 12, 14);
	ROUND_1(c, d, a, b, w, 14, 17, 15);
	ROUND_1(b, c, d, a, w, 15, 22, 16);

	ROUND_2(a, b, c, d, w, 1, 5, 17);
	ROUND_2(d, a, b, c, w, 6, 9, 18);
	ROUND_2(c, d, a, b, w, 11, 14, 19);
	ROUND_2(b, c, d, a, w, 0, 20, 20);
	ROUND_2(a, b, c, d, w, 5, 5, 21);
	ROUND_2(d, a, b, c, w, 10, 9, 22);
	ROUND_2(c, d, a, b, w, 15, 14, 23);
	ROUND_2(b, c, d, a, w, 4, 20, 24);
	ROUND_2(a, b, c, d, w, 9, 5, 25);
	ROUND_2(d, a, b, c, w, 14, 9, 26);
	ROUND_2(c, d, a, b, w, 3, 14, 27);
	ROUND_2(b, c, d, a, w, 8, 20, 28);
	ROUND_2(a, b, c, d, w, 13, 5, 29);
	ROUND_2(d, a, b, c, w, 2, 9, 30);
	ROUND_2(c, d, a, b, w, 7, 14, 31);
	ROUND_2(b, c, d, a, w, 12, 20, 32);

	ROUND_3(a, b, c, d, w, 5, 4, 33);
	ROUND_3(d, a, b, c, w, 8, 11, 34);
	ROUND_3(c, d, a, b, w, 11, 16, 35);
	ROUND_3(b, c, d, a, w, 14, 23, 36);
	ROUND_3(a, b, c, d, w, 1, 4, 37);
	ROUND_3(d, a, b, c, w, 4, 11, 38);
	ROUND_3(c, d, a, b, w, 7, 16, 39);
	ROUND_3(b, c, d, a, w, 10, 23, 40);
	ROUND_3(a, b, c, d, w, 13, 4, 41);
	ROUND_3(d, a, b, c, w, 0, 11, 42);
	ROUND_3(c, d, a, b, w, 3, 16, 43);
	ROUND_3(b, c, d, a, w, 6, 23, 44);
	ROUND_3(a, b, c, d, w, 9, 4, 45);
	ROUND_3(d, a, b, c, w, 12, 11, 46);
	ROUND_3(c, d, a, b, w, 15, 16, 47);
	ROUND_3(b, c, d, a, w, 2, 23, 48);

	ROUND_4(a, b, c, d, w, 0, 6, 49);
	ROUND_4(d, a, b, c, w, 7, 10, 50);
	ROUND_4(c, d, a, b, w, 14, 15, 51);
	ROUND_4(b, c, d, a, w, 5, 21, 52);
	ROUND_4(a, b, c, d, w, 12, 6, 53);
	ROUND_4(d, a, b, c, w, 3, 10, 54);
	ROUND_4(c, d, a, b, w, 10, 15, 55);
	ROUND_4(b, c, d, a, w, 1, 21, 56);
	ROUND_4(a, b, c, d, w, 8, 6, 57);
	ROUND_4(d, a, b, c, w, 15, 10, 58);
	ROUND_4(c, d, a, b, w, 6, 15, 59);
	ROUND_4(b, c, d, a, w, 13, 21, 60);
	ROUND_4(a, b, c, d, w, 4, 6, 61);
	ROUND_4(d, a, b, c, w, 11, 10, 62);
	ROUND_4(c, d, a, b, w, 2, 15, 63);
	ROUND_4(b, c, d, a, w, 9, 21, 64);

	ctx->a += a;
	ctx->b += b;
	ctx->c += c;
	ctx->d += d;
}

static inline md5_ctx *md5_init_checked(void *ptr)
{
	md5_ctx *ctx = (md5_ctx *)ptr;

	memset(ctx, 0, sizeof(md5_ctx));

	ctx->a = A;
	ctx->b = B;
	ctx->c = C;
	ctx->d = D;

	return ctx;
}

md5_ctx *md5_init(void *ptr, size_t size)
{
	if (size < sizeof(md5_ctx))
	{
		return NULL;
	}

	return md5_init_checked(ptr);
}

md5_ctx *md5_new(void)
{
	md5_ctx *ctx = (md5_ctx *)malloc(sizeof(md5_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	return md5_init_checked(ctx);
}

void md5_delete(md5_ctx *ctx)
{
	free(ctx);
}

void md5_reset(md5_ctx *ctx)
{
	memset(ctx, 0, sizeof(md5_ctx));

	ctx->a = A;
	ctx->b = B;
	ctx->c = C;
	ctx->d = D;
}

void md5_update(md5_ctx *ctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t remaining = 0;
	uint64_t unhashed = ctx->size % MD5_BLOCK_SIZE;
	byte_t *pdata = (byte_t *)data;

	// First process the previous data if any.
	if (unhashed != 0)
	{
		uint64_t spill = MD5_BLOCK_SIZE - unhashed;

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

		md5_hash_block(ctx, ctx->internal);
	}

	while (pos + MD5_BLOCK_SIZE <= size)
	{
		memcpy(ctx->internal, pdata + pos, MD5_BLOCK_SIZE);
		md5_hash_block(ctx, ctx->internal);

		ctx->size += MD5_BLOCK_SIZE;
		pos += MD5_BLOCK_SIZE;
	}

	// Copy the remaining data to the internal buffer.
	remaining = size - pos;

	if (remaining > 0)
	{
		ctx->size += remaining;

		memcpy(&ctx->internal[0], pdata + pos, remaining);
	}
}

void md5_final(md5_ctx *ctx, byte_t buffer[MD5_HASH_SIZE])
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
	md5_update(ctx, padding, total_padding);

	// Copy the hash to the buffer, {a,b,c,d} in Little Endian Order.
	memcpy(buffer, &ctx->a, MD5_HASH_SIZE);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(md5_ctx));
}

void md5_hash(void *data, size_t size, byte_t buffer[MD5_HASH_SIZE])
{
	md5_ctx ctx;

	// Initialize the context.
	md5_init_checked(&ctx);

	// Hash the data.
	md5_update(&ctx, data, size);

	// Output the hash
	md5_final(&ctx, buffer);
}
