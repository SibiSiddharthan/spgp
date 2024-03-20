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

// See FIPS 180-4 : Secure Hash Standard

// Initialization vectors
// SHA-384
static const uint64_t H384_0 = 0xCBBB9D5DC1059ED8;
static const uint64_t H384_1 = 0x629A292A367CD507;
static const uint64_t H384_2 = 0x9159015A3070DD17;
static const uint64_t H384_3 = 0x152FECD8F70E5939;
static const uint64_t H384_4 = 0x67332667FFC00B31;
static const uint64_t H384_5 = 0x8EB44A8768581511;
static const uint64_t H384_6 = 0xDB0C2E0D64F98FA7;
static const uint64_t H384_7 = 0x47B5481DBEFA4FA4;

// SHA-512
static const uint64_t H512_0 = 0x6A09E667F3BCC908;
static const uint64_t H512_1 = 0xBB67AE8584CAA73B;
static const uint64_t H512_2 = 0x3C6EF372FE94F82B;
static const uint64_t H512_3 = 0xA54FF53A5F1D36F1;
static const uint64_t H512_4 = 0x510E527FADE682D1;
static const uint64_t H512_5 = 0x9B05688C2B3E6C1F;
static const uint64_t H512_6 = 0x1F83D9ABFB41BD6B;
static const uint64_t H512_7 = 0x5BE0CD19137E2179;

// SHA-512/224
static const uint64_t H512_224_0 = 0x8C3D37C819544DA2;
static const uint64_t H512_224_1 = 0x73E1996689DCD4D6;
static const uint64_t H512_224_2 = 0x1DFAB7AE32FF9C82;
static const uint64_t H512_224_3 = 0x679DD514582F9FCF;
static const uint64_t H512_224_4 = 0x0F6D2B697BD44DA8;
static const uint64_t H512_224_5 = 0x77E36F7304C48942;
static const uint64_t H512_224_6 = 0x3F9D85A86A1D36C8;
static const uint64_t H512_224_7 = 0x1112E6AD91D692A1;

// SHA-512/256
static const uint64_t H512_256_0 = 0x22312194FC2BF72C;
static const uint64_t H512_256_1 = 0x9F555FA3C84C64C2;
static const uint64_t H512_256_2 = 0x2393B86B6F53B151;
static const uint64_t H512_256_3 = 0x963877195940EABD;
static const uint64_t H512_256_4 = 0x96283EE2A88EFFE3;
static const uint64_t H512_256_5 = 0xBE5E1E2553863992;
static const uint64_t H512_256_6 = 0x2B0199FC2C85B8AA;
static const uint64_t H512_256_7 = 0x0EB72DDC81C52CA2;

// SHA-384, SHA-512 Constants
// clang-format off
static const uint64_t K_512[80] = 
{
0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2, 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF, 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC, 0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
};
// clang-format on

// Auxillary functions
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x)    (ROTR_64(x, 28) ^ ROTR_64(x, 34) ^ ROTR_64(x, 39))
#define SIGMA1(x)    (ROTR_64(x, 14) ^ ROTR_64(x, 18) ^ ROTR_64(x, 41))
#define GAMMA0(x)    (ROTR_64(x, 1) ^ ROTR_64(x, 8) ^ ((x) >> 7))
#define GAMMA1(x)    (ROTR_64(x, 19) ^ ROTR_64(x, 61) ^ ((x) >> 6))

#define SHA512_ROUND(I, W, K, T1, T2, A, B, C, D, E, F, G, H) \
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

static void sha512_common_hash_block(sha512_ctx *ctx, byte_t block[SHA512_BLOCK_SIZE])
{
	uint64_t a, b, c, d, e, f, g, h, t1, t2;
	uint64_t w[80];
	uint64_t *temp = (uint64_t *)block;

	for (int32_t i = 0; i < 16; ++i)
	{
		w[i] = BSWAP_64(temp[i]);
	}

	for (int32_t i = 16, j = 0; i < 80; ++i, ++j)
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

	// Rounds 1 - 80
	SHA512_ROUND(0, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(1, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(2, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(3, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(4, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(5, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(6, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(7, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(8, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(9, w, K_512, t1, t2, a, b, c, d, e, f, g, h);

	SHA512_ROUND(10, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(11, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(12, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(13, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(14, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(15, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(16, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(17, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(18, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(19, w, K_512, t1, t2, a, b, c, d, e, f, g, h);

	SHA512_ROUND(20, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(21, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(22, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(23, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(24, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(25, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(26, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(27, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(28, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(29, w, K_512, t1, t2, a, b, c, d, e, f, g, h);

	SHA512_ROUND(30, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(31, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(32, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(33, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(34, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(35, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(36, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(37, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(38, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(39, w, K_512, t1, t2, a, b, c, d, e, f, g, h);

	SHA512_ROUND(40, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(41, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(42, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(43, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(44, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(45, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(46, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(47, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(48, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(49, w, K_512, t1, t2, a, b, c, d, e, f, g, h);

	SHA512_ROUND(50, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(51, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(52, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(53, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(54, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(55, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(56, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(57, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(58, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(59, w, K_512, t1, t2, a, b, c, d, e, f, g, h);

	SHA512_ROUND(60, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(61, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(62, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(63, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(64, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(65, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(66, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(67, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(68, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(69, w, K_512, t1, t2, a, b, c, d, e, f, g, h);

	SHA512_ROUND(70, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(71, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(72, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(73, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(74, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(75, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(76, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(77, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(78, w, K_512, t1, t2, a, b, c, d, e, f, g, h);
	SHA512_ROUND(79, w, K_512, t1, t2, a, b, c, d, e, f, g, h);

	ctx->h0 += a;
	ctx->h1 += b;
	ctx->h2 += c;
	ctx->h3 += d;
	ctx->h4 += e;
	ctx->h5 += f;
	ctx->h6 += g;
	ctx->h7 += h;
}

static void sha512_common_update(sha512_ctx *ctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t remaining = 0;
	uint64_t unhashed = ctx->size_low % SHA512_BLOCK_SIZE;
	byte_t *pdata = (byte_t *)data;

	// First process the previous data if any.
	if (unhashed != 0)
	{
		uint64_t spill = SHA512_BLOCK_SIZE - unhashed;

		if (size < spill)
		{
			memcpy(&ctx->internal[unhashed], pdata, size);
			ctx->size_high += (ctx->size_low + size < ctx->size_low);
			ctx->size_low += size;

			// Nothing to do.
			return;
		}

		memcpy(&ctx->internal[unhashed], pdata, spill);

		ctx->size_high += (ctx->size_low + spill < ctx->size_low);
		ctx->size_low += spill;
		pos += spill;

		sha512_common_hash_block(ctx, ctx->internal);
	}

	while (pos + SHA512_BLOCK_SIZE <= size)
	{
		sha512_common_hash_block(ctx, (pdata + pos));

		ctx->size_high += (ctx->size_low + SHA512_BLOCK_SIZE < ctx->size_low);
		ctx->size_low += SHA512_BLOCK_SIZE;
		pos += SHA512_BLOCK_SIZE;
	}

	// Copy the remaining data to the internal buffer.
	remaining = size - pos;

	if (remaining > 0)
	{
		ctx->size_high += (ctx->size_low + remaining < ctx->size_low);
		ctx->size_low += remaining;

		memcpy(&ctx->internal[0], pdata + pos, remaining);
	}
}

static void sha512_common_pre_final(sha512_ctx *ctx)
{
	uint64_t bits_high = BSWAP_64((ctx->size_high << 3) | (ctx->size_low >> 61));
	uint64_t bits_low = BSWAP_64(ctx->size_low << 3);
	uint64_t zero_padding = ((128 + 112) - ((ctx->size_low + 1) % 128)) % 128; // (l+1+k)mod128 = 112mod128
	uint64_t total_padding = 0;
	byte_t padding[256] = {0};

	// First byte.
	padding[0] = 0x80;
	total_padding += 1;

	// Zero padding
	total_padding += zero_padding;

	// Append message length (bits) in Big Endian order.
	memcpy(&padding[total_padding], &bits_high, sizeof(uint64_t));
	total_padding += 8;
	
	memcpy(&padding[total_padding], &bits_low, sizeof(uint64_t));
	total_padding += 8;

	// Final Hash.
	sha512_common_update(ctx, padding, total_padding);
}

static void sha512_quick_reset(sha512_ctx *ctx)
{
	ctx->h0 = H512_0;
	ctx->h1 = H512_1;
	ctx->h2 = H512_2;
	ctx->h3 = H512_3;
	ctx->h4 = H512_4;
	ctx->h5 = H512_5;
	ctx->h6 = H512_6;
	ctx->h7 = H512_7;
}

sha512_ctx *sha512_init(void)
{
	sha512_ctx *ctx = malloc(sizeof(sha512_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	memset(ctx, 0, sizeof(sha512_ctx));
	sha512_quick_reset(ctx);

	return ctx;
}

void sha512_free(sha512_ctx *ctx)
{
	free(ctx);
}

void sha512_reset(sha512_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha512_ctx));
	sha512_quick_reset(ctx);
}

void sha512_update(sha512_ctx *ctx, void *data, size_t size)
{
	return sha512_common_update(ctx, data, size);
}

void sha512_final(sha512_ctx *ctx, byte_t buffer[SHA512_HASH_SIZE])
{
	uint64_t *words = (uint64_t *)buffer;

	// Final hash step.
	sha512_common_pre_final(ctx);

	// Copy the hash to the buffer {h0,h1,h2,h3,h4,h5,h6,h7} in Big Endian Order.
	words[0] = BSWAP_64(ctx->h0);
	words[1] = BSWAP_64(ctx->h1);
	words[2] = BSWAP_64(ctx->h2);
	words[3] = BSWAP_64(ctx->h3);
	words[4] = BSWAP_64(ctx->h4);
	words[5] = BSWAP_64(ctx->h5);
	words[6] = BSWAP_64(ctx->h6);
	words[7] = BSWAP_64(ctx->h7);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha512_ctx));
}

int32_t sha512_quick_hash(void *data, size_t size, byte_t buffer[SHA512_HASH_SIZE])
{
	// Initialize the context.
	sha512_ctx *ctx = sha512_init();

	if (ctx == NULL)
	{
		return -1;
	}

	// Hash the data.
	sha512_update(ctx, data, size);

	// Output the hash
	sha512_final(ctx, buffer);

	// Free the context.
	sha512_free(ctx);

	return 0;
}

static void sha384_quick_reset(sha384_ctx *ctx)
{
	ctx->h0 = H384_0;
	ctx->h1 = H384_1;
	ctx->h2 = H384_2;
	ctx->h3 = H384_3;
	ctx->h4 = H384_4;
	ctx->h5 = H384_5;
	ctx->h6 = H384_6;
	ctx->h7 = H384_7;
}

sha384_ctx *sha384_init(void)
{
	sha384_ctx *ctx = malloc(sizeof(sha384_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	memset(ctx, 0, sizeof(sha384_ctx));
	sha384_quick_reset(ctx);

	return ctx;
}

void sha384_free(sha384_ctx *ctx)
{
	free(ctx);
}

void sha384_reset(sha384_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha384_ctx));
	sha384_quick_reset(ctx);
}

void sha384_update(sha384_ctx *ctx, void *data, size_t size)
{
	return sha512_common_update(ctx, data, size);
}

void sha384_final(sha384_ctx *ctx, byte_t buffer[SHA384_HASH_SIZE])
{
	uint64_t *words = (uint64_t *)buffer;

	// Final hash step.
	sha512_common_pre_final(ctx);

	// Copy the hash to the buffer {h0,h1,h2,h3,h4,h5} in Big Endian Order.
	words[0] = BSWAP_64(ctx->h0);
	words[1] = BSWAP_64(ctx->h1);
	words[2] = BSWAP_64(ctx->h2);
	words[3] = BSWAP_64(ctx->h3);
	words[4] = BSWAP_64(ctx->h4);
	words[5] = BSWAP_64(ctx->h5);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha384_ctx));
}

int32_t sha384_quick_hash(void *data, size_t size, byte_t buffer[SHA384_HASH_SIZE])
{
	// Initialize the context.
	sha384_ctx *ctx = sha384_init();

	if (ctx == NULL)
	{
		return -1;
	}

	// Hash the data.
	sha384_update(ctx, data, size);

	// Output the hash
	sha384_final(ctx, buffer);

	// Free the context.
	sha384_free(ctx);

	return 0;
}

static void sha512_224_quick_rest(sha512_224_ctx *ctx)
{
	ctx->h0 = H512_224_0;
	ctx->h1 = H512_224_1;
	ctx->h2 = H512_224_2;
	ctx->h3 = H512_224_3;
	ctx->h4 = H512_224_4;
	ctx->h5 = H512_224_5;
	ctx->h6 = H512_224_6;
	ctx->h7 = H512_224_7;
}

sha512_224_ctx *sha512_224_init(void)
{
	sha512_224_ctx *ctx = malloc(sizeof(sha512_224_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	memset(ctx, 0, sizeof(sha512_224_ctx));
	sha512_224_quick_rest(ctx);

	return ctx;
}

void sha512_224_free(sha512_224_ctx *ctx)
{
	free(ctx);
}

void sha512_224_reset(sha512_224_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha512_224_ctx));
	sha512_224_quick_rest(ctx);
}

void sha512_224_update(sha512_224_ctx *ctx, void *data, size_t size)
{
	return sha512_common_update(ctx, data, size);
}

void sha512_224_final(sha512_224_ctx *ctx, byte_t buffer[SHA512_224_HASH_SIZE])
{
	uint64_t *words = (uint64_t *)buffer;

	// Final hash step.
	sha512_common_pre_final(ctx);

	// Copy the hash to the buffer {h0,h1,h2,h3(leftmost 32 bits)} in Big Endian Order.
	words[0] = BSWAP_64(ctx->h0);
	words[1] = BSWAP_64(ctx->h1);
	words[2] = BSWAP_64(ctx->h2);
	*(uint32_t *)&words[3] = (uint32_t)BSWAP_64(ctx->h3); // Truncate to 32 bits.

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha512_224_ctx));
}

int32_t sha512_224_quick_hash(void *data, size_t size, byte_t buffer[SHA512_224_HASH_SIZE])
{
	// Initialize the context.
	sha512_224_ctx *ctx = sha512_224_init();

	if (ctx == NULL)
	{
		return -1;
	}

	// Hash the data.
	sha512_224_update(ctx, data, size);

	// Output the hash
	sha512_224_final(ctx, buffer);

	// Free the context.
	sha512_224_free(ctx);

	return 0;
}

static void sha512_256_quick_rest(sha512_256_ctx *ctx)
{
	ctx->h0 = H512_256_0;
	ctx->h1 = H512_256_1;
	ctx->h2 = H512_256_2;
	ctx->h3 = H512_256_3;
	ctx->h4 = H512_256_4;
	ctx->h5 = H512_256_5;
	ctx->h6 = H512_256_6;
	ctx->h7 = H512_256_7;
}

sha512_256_ctx *sha512_256_init(void)
{
	sha512_256_ctx *ctx = malloc(sizeof(sha512_256_ctx));

	if (ctx == NULL)
	{
		return NULL;
	}

	memset(ctx, 0, sizeof(sha512_256_ctx));
	sha512_256_quick_rest(ctx);

	return ctx;
}

void sha512_256_free(sha512_256_ctx *ctx)
{
	free(ctx);
}

void sha512_256_reset(sha512_256_ctx *ctx)
{
	memset(ctx, 0, sizeof(sha512_256_ctx));
	sha512_256_quick_rest(ctx);
}

void sha512_256_update(sha512_256_ctx *ctx, void *data, size_t size)
{
	return sha512_common_update(ctx, data, size);
}

void sha512_256_final(sha512_256_ctx *ctx, byte_t buffer[SHA512_256_HASH_SIZE])
{
	uint64_t *words = (uint64_t *)buffer;

	// Final hash step.
	sha512_common_pre_final(ctx);

	// Copy the hash to the buffer {h0,h1,h2,h3} in Big Endian Order.
	words[0] = BSWAP_64(ctx->h0);
	words[1] = BSWAP_64(ctx->h1);
	words[2] = BSWAP_64(ctx->h2);
	words[3] = BSWAP_64(ctx->h3);

	// Zero the context for security reasons.
	memset(ctx, 0, sizeof(sha512_256_ctx));
}

int32_t sha512_256_quick_hash(void *data, size_t size, byte_t buffer[SHA512_256_HASH_SIZE])
{
	// Initialize the context.
	sha512_256_ctx *ctx = sha512_256_init();

	if (ctx == NULL)
	{
		return -1;
	}

	// Hash the data.
	sha512_256_update(ctx, data, size);

	// Output the hash
	sha512_256_final(ctx, buffer);

	// Free the context.
	sha512_256_free(ctx);

	return 0;
}
