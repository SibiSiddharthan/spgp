/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <types.h>
#include <byteswap.h>
#include <minmax.h>
#include <round.h>

// See NIST SP 800-38D Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC

typedef struct _gcm_ctx
{
	byte_t h[16];
	byte_t j[16];
	byte_t s[16];
	byte_t icb[16];

	size_t data_size;
	size_t ad_size;

	void *key;
	void (*encrypt)(void *key, void *plaintext, void *ciphertext);
} gcm_ctx;

static inline void block_multiplication(uint64_t x[2], uint64_t y[2])
{
	const byte_t R[16] = {0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	uint64_t *r = (uint64_t *)R;

	uint64_t z[2], v[2];

	z[0] = 0;
	z[1] = 0;

	v[0] = BSWAP_64(x[0]);
	v[1] = BSWAP_64(x[1]);

	for (uint8_t i = 0; i < 128; ++i)
	{
		if (y[i / 64] & (1ull << i % 64))
		{
			z[0] ^= v[0];
			z[1] ^= v[1];
		}

		if (v[0] & 0x1)
		{
			v[0] = ((v[0] >> 1) | ((v[1] & 0x1) << 63)) ^ r[0];
			v[1] = (v[1] >> 1) ^ r[1];
		}
		else
		{
			v[0] = (v[0] >> 1) | ((v[1] & 0x1) << 63);
			v[1] = v[1] >> 1;
		}
	}

	x[0] = BSWAP_64(z[0]);
	x[1] = BSWAP_64(z[1]);
}

void ghash(void *state, void *key, void *data, size_t size)
{

	uint64_t processed = 0;

	uint64_t *x = data;
	uint64_t *y = state;
	uint64_t *h = key;

	while (processed < size)
	{

		uint64_t z[2], v[2];

		y[0] ^= x[0];
		y[1] ^= x[1];

		z[0] = 0;
		z[1] = 0;

		v[0] = BSWAP_64(y[0]);
		v[1] = BSWAP_64(y[1]);

		block_multiplication(y, h);

		// Move by 16 bytes.
		x += 2;
		processed += 16;
	}
}

uint64_t gctr_update(gcm_ctx *gctx, void *icb, void *in, size_t in_size, void *out, size_t out_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	uint32_t *pc = (uint32_t *)((byte_t *)icb + 12);
	uint32_t counter = BSWAP_32(*pc);

	byte_t buffer[16];
	uint64_t *b = (uint64_t *)buffer;

	// Make sure input is a multiple of block_size
	if (in_size % block_size != 0)
	{
		return 0;
	}

	if (in_size < out_size)
	{
		return 0;
	}

	while (processed < in_size)
	{
		uint64_t *x = (uint64_t *)(pin + processed);
		uint64_t *y = (uint64_t *)(pout + processed);

		gctx->encrypt(gctx->key, icb, buffer);

		y[0] = b[0] ^ x[0];
		y[1] = b[1] ^ x[1];

		++counter;
		*pc = BSWAP_32(counter);

		result += block_size;
		processed += block_size;
	}

	return result;
}

uint64_t gctr_final(gcm_ctx *gctx, void *icb, void *in, size_t in_size, void *out, size_t out_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	uint32_t *pc = (uint32_t *)((byte_t *)icb + 12);
	uint32_t counter = BSWAP_32(*pc);

	byte_t buffer[16];
	uint64_t *b = (uint64_t *)buffer;

	if (in_size < out_size)
	{
		return 0;
	}

	while (processed + block_size <= in_size)
	{
		uint64_t *x = (uint64_t *)(pin + processed);
		uint64_t *y = (uint64_t *)(pout + processed);

		gctx->encrypt(gctx->key, icb, buffer);

		y[0] = b[0] ^ x[0];
		y[1] = b[1] ^ x[1];

		++counter;
		*pc = BSWAP_32(counter);

		result += block_size;
		processed += block_size;
	}

	remaining = in_size - processed;

	gctx->encrypt(gctx->key, icb, buffer);

	for (uint8_t i = 0; i < remaining; ++i)
	{
		pout[processed + i] = pin[processed + i] ^ buffer[i];
	}

	result += remaining;

	return result;
}

int32_t gcm_init(gcm_ctx *gctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size)
{
	byte_t zero[16] = {0};
	byte_t buffer[16];

	// Check IV size
	if ((iv_size < 12 || iv_size > 16) && iv_size != 8 && iv_size != 4)
	{
		return -1;
	}

	// Initialize H
	gctx->encrypt(gctx->key, zero, gctx->h);

	// Initialize J
	if (iv_size == 12)
	{
		memcpy(gctx->j, iv, 12);
		gctx->j[15] = 1;
	}
	else
	{
		size_t iv_rd_size = ROUND_DOWN(iv_size, 16);

		uint64_t *pb = (uint64_t *)buffer;

		ghash(gctx->j, gctx->h, iv, iv_rd_size);

		if (iv_rd_size < iv_size)
		{
			memset(buffer, 0, 16);
			memcpy(buffer, (byte_t *)iv + iv_rd_size, iv_size - iv_rd_size);
			ghash(gctx->j, gctx->h, buffer, 16);
		}

		pb[0] = 0;
		pb[1] = BSWAP_64(iv_size);

		ghash(gctx->j, gctx->h, buffer, 16);
	}

	// Calculate ghash for associated data
	size_t ad_rd_size = ROUND_DOWN(ad_size, 16);

	ghash(gctx->s, gctx->h, associated_data, ad_rd_size);

	if (ad_rd_size < ad_size)
	{
		memset(buffer, 0, 16);
		memcpy(buffer, (byte_t *)associated_data + ad_rd_size, ad_size - ad_rd_size);
		ghash(gctx->s, gctx->h, buffer, 16);
	}

	gctx->ad_size = ad_size;

	// Set ICB
	uint32_t *counter = NULL;

	memcpy(gctx->icb, gctx->j, 16);
	counter = (uint32_t *)&gctx->icb[12];

	*counter = BSWAP_32(*counter);
	*counter += 1;
	*counter = BSWAP_32(*counter);

	return 0;
}

uint64_t gcm_ae_update(gcm_ctx *gctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;

	result = gctr_update(gctx, gctx->icb, plaintext, plaintext_size, ciphertext, ciphertext_size);
	gctx->data_size += result;

	ghash(gctx->s, gctx->h, ciphertext, result);

	return result;
}

uint64_t gcm_ae_final(gcm_ctx *gctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size, void *tag,
					  size_t tag_size)
{
	uint64_t result = 0;
	uint64_t rd = 0;

	byte_t buffer[16] = {0};
	uint64_t *pb = (uint64_t *)buffer;

	result = gctr_final(gctx, gctx->icb, plaintext, plaintext_size, ciphertext, ciphertext_size);
	gctx->data_size += result;

	rd = ROUND_DOWN(result, 16);

	ghash(gctx->s, gctx->h, ciphertext, rd);

	if (rd < result)
	{
		memset(buffer, 0, 16);
		memcpy(buffer, (byte_t *)ciphertext + rd, result - rd);
		ghash(gctx->s, gctx->h, buffer, 16);
	}

	pb[0] = BSWAP_64(gctx->ad_size);
	pb[1] = BSWAP_64(gctx->data_size);

	ghash(gctx->s, gctx->h, buffer, 16);

	gctr_update(gctx, gctx->j, gctx->s, 16, buffer, 16);
	memcpy(tag, buffer, MIN(tag_size, 16));

	return 0;
}

uint64_t gcm_ad_update(gcm_ctx *gctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;

	result = gctr_update(gctx, gctx->icb, ciphertext, ciphertext_size, plaintext, plaintext_size);
	gctx->data_size += result;

	ghash(gctx->s, gctx->h, ciphertext, result);

	return result;
}

uint64_t gcm_ad_final(gcm_ctx *gctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size, void *tag,
					  size_t tag_size)
{
	uint64_t result = 0;
	uint64_t rd = 0;

	byte_t buffer[16] = {0};
	uint64_t *pb = (uint64_t *)buffer;

	result = gctr_final(gctx, gctx->icb, plaintext, plaintext_size, ciphertext, ciphertext_size);
	gctx->data_size += result;

	rd = ROUND_DOWN(result, 16);

	ghash(gctx->s, gctx->h, ciphertext, rd);

	if (rd < result)
	{
		memset(buffer, 0, 16);
		memcpy(buffer, (byte_t *)ciphertext + rd, result - rd);
		ghash(gctx->s, gctx->h, buffer, 16);
	}

	pb[0] = BSWAP_64(gctx->ad_size);
	pb[1] = BSWAP_64(gctx->data_size);

	ghash(gctx->s, gctx->h, buffer, 16);

	gctr_update(gctx, gctx->j, gctx->s, 16, buffer, 16);

	if(memcmp(tag,buffer,tag_size) != 0)
	{
		return -1ull;
	}

	return 0;
}