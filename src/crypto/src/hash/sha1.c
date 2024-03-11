/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <byteswap.h>
#include <rotate.h>
#include <sha.h>

// See RFC 3174 : The Secure Hash Algorithm (SHA1)
// See FIPS 180-4 : Secure Hash Standard

// Initialization vectors
static uint32_t H0 = 0x67452301;
static uint32_t H1 = 0xEFCDAB89;
static uint32_t H2 = 0x98BADCFE;
static uint32_t H3 = 0x10325476;
static uint32_t H4 = 0xC3D2E1F0;

// SHA-1 Constants
static uint32_t K0 = 0x5A827999; // Rounds 1 - 20
static uint32_t K1 = 0x6ED9EBA1; // Rounds 21 - 40
static uint32_t K2 = 0x8F1BBCDC; // Rounds 41 - 60
static uint32_t K3 = 0xCA62C1D6; // Rounds 61 - 80

// Auxillary functions
#define CH(x, y, z)     (((x) & (y)) | (~(x) & (z)))              // Rounds 1 - 20
#define PARITY(x, y, z) ((x) ^ (y) ^ (z))                         // Rounds 21 - 40, 61 - 80
#define MAJ(x, y, z)    (((x) & (y)) | ((x) & (z)) | ((y) & (z))) // Rounds 41 - 60

#define SHA1_ROUND(I, F, K, W, T, A, B, C, D, E)       \
	{                                                  \
		T = ROTL_32(A, 5) + F(B, C, D) + E + W[I] + K; \
		E = D;                                         \
		D = C;                                         \
		C = ROTL_32(B, 30);                            \
		B = A;                                         \
		A = T;                                         \
	}

static void sha1_hash_block(sha1_ctx *ctx, byte_t block[SHA1_BLOCK_SIZE])
{
	uint32_t a, b, c, d, e, t;
	uint32_t w[80];
	uint32_t *temp = (uint32_t *)block;

	for (int32_t i = 0; i < 16; ++i)
	{
		w[i] = BSWAP_32(temp[i]);
	}

	for (int32_t i = 16, j = 0; i < 79; ++i, ++j)
	{
		// j = i + 16
		w[i] = ROTL_32((w[j + 13] ^ w[j + 8] ^ w[j + 2] ^ w[j]), 1);
	}

	a = ctx->h0;
	b = ctx->h1;
	c = ctx->h2;
	d = ctx->h3;
	e = ctx->h4;

	// Rounds 1 - 20
	SHA1_ROUND(0, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(1, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(2, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(3, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(4, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(5, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(6, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(7, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(8, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(9, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(10, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(11, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(12, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(13, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(14, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(15, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(16, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(17, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(18, CH, K0, w, t, a, b, c, d, e);
	SHA1_ROUND(19, CH, K0, w, t, a, b, c, d, e);

	// Rounds 21 - 40
	SHA1_ROUND(20, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(21, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(22, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(23, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(24, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(25, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(26, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(27, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(28, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(29, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(30, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(31, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(32, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(33, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(34, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(35, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(36, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(37, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(38, PARITY, K1, w, t, a, b, c, d, e);
	SHA1_ROUND(39, PARITY, K1, w, t, a, b, c, d, e);

	// Rounds 41 - 60
	SHA1_ROUND(40, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(41, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(42, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(43, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(44, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(45, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(46, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(47, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(48, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(49, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(50, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(51, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(52, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(53, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(54, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(55, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(56, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(57, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(58, MAJ, K2, w, t, a, b, c, d, e);
	SHA1_ROUND(59, MAJ, K2, w, t, a, b, c, d, e);

	// Rounds 61 - 80
	SHA1_ROUND(60, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(61, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(62, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(63, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(64, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(65, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(66, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(67, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(68, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(69, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(70, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(71, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(72, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(73, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(74, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(75, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(76, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(77, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(78, PARITY, K3, w, t, a, b, c, d, e);
	SHA1_ROUND(79, PARITY, K3, w, t, a, b, c, d, e);

	ctx->h0 += a;
	ctx->h1 += b;
	ctx->h2 += c;
	ctx->h3 += d;
	ctx->h4 += d;
}

sha1_ctx *sha1_init(void)
{
	sha1_ctx *ctx = malloc(sizeof(sha1_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	memset(ctx, 0, sizeof(sha1_ctx));

	ctx->h0 = H0;
	ctx->h1 = H1;
	ctx->h2 = H2;
	ctx->h3 = H3;
	ctx->h4 = H4;

	return ctx;
}

void sha1_free(sha1_ctx *ctx)
{
	free(ctx);
}

void sha1_reset(sha1_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha1_ctx));

	ctx->h0 = H0;
	ctx->h1 = H1;
	ctx->h2 = H2;
	ctx->h3 = H3;
	ctx->h4 = H4;
}

void sha1_update(sha1_ctx *ctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t remaining = 0;
	uint64_t unhashed = ctx->size % SHA1_BLOCK_SIZE;
	byte_t *pdata = (byte_t *)data;

	// First process the previous data if any.
	if (unhashed != 0)
	{
		uint64_t spill = SHA1_BLOCK_SIZE - unhashed;

		memcpy(&ctx->internal[unhashed], pdata, spill);

		ctx->size += spill;
		pos += spill;

		sha1_hash_block(ctx, ctx->internal);
	}

	while (pos + SHA1_BLOCK_SIZE <= size)
	{
		sha1_hash_block(ctx, (pdata + pos));

		ctx->size += SHA1_BLOCK_SIZE;
		pos += SHA1_BLOCK_SIZE;
	}

	// Copy the remaining data to the internal buffer.
	remaining = size - pos;

	if (remaining > 0)
	{
		ctx->size += remaining;

		memcpy(&ctx->internal[0], pdata + pos, remaining);
	}
}

void sha1_final(sha1_ctx *ctx, byte_t buffer[SHA1_HASH_SIZE])
{
	uint64_t bits = BSWAP_64(ctx->size * 8);
	uint64_t zero_padding = (64 + 56 - ((ctx->size + 1) % 64)) % 64; // (l+1+k)mod64 = 56mod64
	uint64_t total_padding = 0;
	byte_t padding[128] = {0};

	// First byte.
	padding[0] = 0x80;
	total_padding += 1;

	// Zero padding
	total_padding += zero_padding;

	// Append message length (bits) in Big Endian order.
	memcpy(&padding[total_padding], &bits, sizeof(uint64_t));
	total_padding += 8;

	// Final Hash.
	sha1_update(ctx, padding, total_padding);

	// Copy the hash to the buffer, {h0,h1,h2,h3,h4}.
	memcpy(buffer, &ctx->h0, SHA1_HASH_SIZE);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha1_ctx));
}

int32_t sha1_quick_hash(void *data, size_t size, byte_t buffer[SHA1_HASH_SIZE])
{
	// Initialize the context.
	sha1_ctx *ctx = sha1_init();

	if (ctx == NULL)
	{
		return -1;
	}

	// Hash the data.
	sha1_update(ctx, data, size);

	// Output the hash
	sha1_final(ctx, buffer);

	// Free the context.
	sha1_free(ctx);

	return 0;
}
