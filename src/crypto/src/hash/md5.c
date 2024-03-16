/*
   Copyright (c) 2024 Sibi Siddharthan

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
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
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

md5_ctx *md5_init(void)
{
	md5_ctx *ctx = malloc(sizeof(md5_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	memset(ctx, 0, sizeof(md5_ctx));

	ctx->a = A;
	ctx->b = B;
	ctx->c = C;
	ctx->d = D;

	return ctx;
}

void md5_free(md5_ctx *ctx)
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

		memcpy(&ctx->internal[unhashed], pdata, spill);

		ctx->size += spill;
		pos += spill;

		md5_hash_block(ctx, ctx->internal);
	}

	while (pos + MD5_BLOCK_SIZE <= size)
	{
		md5_hash_block(ctx, (pdata + pos));

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

int32_t md5_quick_hash(void *data, size_t size, byte_t buffer[MD5_HASH_SIZE])
{
	// Initialize the context.
	md5_ctx *ctx = md5_init();

	if (ctx == NULL)
	{
		return -1;
	}

	// Hash the data.
	md5_update(ctx, data, size);

	// Output the hash
	md5_final(ctx, buffer);

	// Free the context.
	md5_free(ctx);

	return 0;
}
