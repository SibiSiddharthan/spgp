/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <sha.h>

#include <stdlib.h>
#include <string.h>

// See NIST FIPS 180-4 : Secure Hash Standard (SHS)

// Initialization vectors
// SHA-224
static const uint32_t H224_0 = 0xC1059ED8;
static const uint32_t H224_1 = 0x367CD507;
static const uint32_t H224_2 = 0x3070DD17;
static const uint32_t H224_3 = 0xF70E5939;
static const uint32_t H224_4 = 0xFFC00B31;
static const uint32_t H224_5 = 0x68581511;
static const uint32_t H224_6 = 0x64F98FA7;
static const uint32_t H224_7 = 0xBEFA4FA4;

// SHA-256
static const uint32_t H256_0 = 0x6A09E667;
static const uint32_t H256_1 = 0xBB67AE85;
static const uint32_t H256_2 = 0x3C6EF372;
static const uint32_t H256_3 = 0xA54FF53A;
static const uint32_t H256_4 = 0x510E527F;
static const uint32_t H256_5 = 0x9B05688C;
static const uint32_t H256_6 = 0x1F83D9AB;
static const uint32_t H256_7 = 0x5BE0CD19;

// SHA-224, SHA-256 Constants
// clang-format off
static const uint32_t K_256[64] = 
{
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE,	0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA,	0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85,	0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F,	0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};
// clang-format on

// Auxillary functions
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x)    (ROTR_32(x, 2) ^ ROTR_32(x, 13) ^ ROTR_32(x, 22))
#define SIGMA1(x)    (ROTR_32(x, 6) ^ ROTR_32(x, 11) ^ ROTR_32(x, 25))
#define GAMMA0(x)    (ROTR_32(x, 7) ^ ROTR_32(x, 18) ^ ((x) >> 3))
#define GAMMA1(x)    (ROTR_32(x, 17) ^ ROTR_32(x, 19) ^ ((x) >> 10))

#define SHA256_ROUND(I, W, K, T1, T2, A, B, C, D, E, F, G, H) \
	{                                                         \
		T1 = H + SIGMA1(E) + CH(E, F, G) + K[I] + W[I];       \
		T2 = SIGMA0(A) + MAJ(A, B, C);                        \
		H = G;                                                \
		G = F;                                                \
		F = E;                                                \
		E = D + T1;                                           \
		D = C;                                                \
		C = B;                                                \
		B = A;                                                \
		A = T1 + T2;                                          \
	}

static void sha256_common_hash_block(sha256_ctx *ctx, byte_t block[SHA256_BLOCK_SIZE])
{
	uint32_t a, b, c, d, e, f, g, h, t1, t2;
	uint32_t w[64];
	uint32_t *temp = (uint32_t *)block;

	for (int32_t i = 0; i < 16; ++i)
	{
		w[i] = BSWAP_32(temp[i]);
	}

	for (int32_t i = 16, j = 0; i < 64; ++i, ++j)
	{
		// i = j + 16
		w[i] = GAMMA1(w[j + 14]) + w[j + 9] + GAMMA0(w[j + 1]) + w[j];
	}

	a = ctx->h0;
	b = ctx->h1;
	c = ctx->h2;
	d = ctx->h3;
	e = ctx->h4;
	f = ctx->h5;
	g = ctx->h6;
	h = ctx->h7;

	// Rounds 1 - 64
	SHA256_ROUND(0, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(1, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(2, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(3, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(4, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(5, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(6, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(7, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(8, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(9, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(10, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(11, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(12, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(13, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(14, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(15, w, K_256, t1, t2, a, b, c, d, e, f, g, h);

	SHA256_ROUND(16, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(17, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(18, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(19, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(20, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(21, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(22, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(23, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(24, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(25, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(26, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(27, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(28, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(29, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(30, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(31, w, K_256, t1, t2, a, b, c, d, e, f, g, h);

	SHA256_ROUND(32, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(33, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(34, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(35, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(36, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(37, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(38, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(39, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(40, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(41, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(42, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(43, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(44, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(45, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(46, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(47, w, K_256, t1, t2, a, b, c, d, e, f, g, h);

	SHA256_ROUND(48, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(49, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(50, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(51, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(52, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(53, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(54, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(55, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(56, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(57, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(58, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(59, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(60, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(61, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(62, w, K_256, t1, t2, a, b, c, d, e, f, g, h);
	SHA256_ROUND(63, w, K_256, t1, t2, a, b, c, d, e, f, g, h);

	ctx->h0 += a;
	ctx->h1 += b;
	ctx->h2 += c;
	ctx->h3 += d;
	ctx->h4 += e;
	ctx->h5 += f;
	ctx->h6 += g;
	ctx->h7 += h;
}

static void sha256_common_update(sha256_ctx *ctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t remaining = 0;
	uint64_t unhashed = ctx->size % SHA256_BLOCK_SIZE;
	byte_t *pdata = (byte_t *)data;

	// First process the previous data if any.
	if (unhashed != 0)
	{
		uint64_t spill = SHA256_BLOCK_SIZE - unhashed;

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

		sha256_common_hash_block(ctx, ctx->internal);
	}

	while (pos + SHA256_BLOCK_SIZE <= size)
	{
		memcpy(ctx->internal, pdata + pos, SHA256_BLOCK_SIZE);
		sha256_common_hash_block(ctx, ctx->internal);

		ctx->size += SHA256_BLOCK_SIZE;
		pos += SHA256_BLOCK_SIZE;
	}

	// Copy the remaining data to the internal buffer.
	remaining = size - pos;

	if (remaining > 0)
	{
		ctx->size += remaining;

		memcpy(&ctx->internal[0], pdata + pos, remaining);
	}
}

static void sha256_common_pre_final(sha256_ctx *ctx)
{
	uint64_t bits = BSWAP_64(ctx->size * 8);
	uint64_t zero_padding = ((64 + 56) - ((ctx->size + 1) % 64)) % 64; // (l+1+k)mod64 = 56mod64
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
	sha256_common_update(ctx, padding, total_padding);
}

void sha256_init(sha256_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha256_ctx));

	ctx->h0 = H256_0;
	ctx->h1 = H256_1;
	ctx->h2 = H256_2;
	ctx->h3 = H256_3;
	ctx->h4 = H256_4;
	ctx->h5 = H256_5;
	ctx->h6 = H256_6;
	ctx->h7 = H256_7;
}

void sha256_reset(sha256_ctx *ctx)
{
	sha256_init(ctx);
}

void sha256_update(sha256_ctx *ctx, void *data, size_t size)
{
	return sha256_common_update(ctx, data, size);
}

void sha256_final(sha256_ctx *ctx, byte_t buffer[SHA256_HASH_SIZE])
{
	uint32_t *words = (uint32_t *)buffer;

	// Final hash step.
	sha256_common_pre_final(ctx);

	// Copy the hash to the buffer {h0,h1,h2,h3,h4,h5,h6,h7} in Big Endian Order.
	words[0] = BSWAP_32(ctx->h0);
	words[1] = BSWAP_32(ctx->h1);
	words[2] = BSWAP_32(ctx->h2);
	words[3] = BSWAP_32(ctx->h3);
	words[4] = BSWAP_32(ctx->h4);
	words[5] = BSWAP_32(ctx->h5);
	words[6] = BSWAP_32(ctx->h6);
	words[7] = BSWAP_32(ctx->h7);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha256_ctx));
}

void sha256_hash(void *data, size_t size, byte_t buffer[SHA256_HASH_SIZE])
{
	sha256_ctx ctx;

	// Initialize the context.
	sha256_init(&ctx);

	// Hash the data.
	sha256_update(&ctx, data, size);

	// Output the hash
	sha256_final(&ctx, buffer);
}

void sha224_init(sha224_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha224_ctx));

	ctx->h0 = H224_0;
	ctx->h1 = H224_1;
	ctx->h2 = H224_2;
	ctx->h3 = H224_3;
	ctx->h4 = H224_4;
	ctx->h5 = H224_5;
	ctx->h6 = H224_6;
	ctx->h7 = H224_7;
}

void sha224_reset(sha224_ctx *ctx)
{
	sha224_init(ctx);
}

void sha224_update(sha224_ctx *ctx, void *data, size_t size)
{
	return sha256_common_update(ctx, data, size);
}

void sha224_final(sha224_ctx *ctx, byte_t buffer[SHA224_HASH_SIZE])
{
	uint32_t *words = (uint32_t *)buffer;

	// Final hash step.
	sha256_common_pre_final(ctx);

	// Copy the hash to the buffer {h0,h1,h2,h3,h4,h5,h6} in Big Endian Order.
	words[0] = BSWAP_32(ctx->h0);
	words[1] = BSWAP_32(ctx->h1);
	words[2] = BSWAP_32(ctx->h2);
	words[3] = BSWAP_32(ctx->h3);
	words[4] = BSWAP_32(ctx->h4);
	words[5] = BSWAP_32(ctx->h5);
	words[6] = BSWAP_32(ctx->h6);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha224_ctx));
}

void sha224_hash(void *data, size_t size, byte_t buffer[SHA224_HASH_SIZE])
{
	sha224_ctx ctx;

	// Initialize the context.
	sha224_init(&ctx);

	// Hash the data.
	sha224_update(&ctx, data, size);

	// Output the hash
	sha224_final(&ctx, buffer);
}
