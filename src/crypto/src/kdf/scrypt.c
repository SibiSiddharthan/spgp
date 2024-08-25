/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <hmac.h>
#include <byteswap.h>
#include <minmax.h>
#include <rotate.h>
#include <round.h>

// Refer RFC 7914 : The scrypt Password-Based Key Derivation Function

#define SALSA20_BLOCK_WORDS 16

uint32_t pbkdf2(hmac_algorithm algorithm, void *password, size_t password_size, void *salt, size_t salt_size, uint32_t iteration_count,
				void *key, size_t key_size);

#define SALSA20_ROUND(X)                     \
	{                                        \
		X[4] ^= ROTL_32(X[0] + X[12], 7);    \
		X[8] ^= ROTL_32(X[4] + X[0], 9);     \
		X[12] ^= ROTL_32(X[8] + X[4], 13);   \
		X[0] ^= ROTL_32(X[12] + X[8], 18);   \
		X[9] ^= ROTL_32(X[5] + X[1], 7);     \
		X[13] ^= ROTL_32(X[9] + X[5], 9);    \
		X[1] ^= ROTL_32(X[13] + X[9], 13);   \
		X[5] ^= ROTL_32(X[1] + X[13], 18);   \
		X[14] ^= ROTL_32(X[10] + X[6], 7);   \
		X[2] ^= ROTL_32(X[14] + X[10], 9);   \
		X[6] ^= ROTL_32(X[2] + X[14], 13);   \
		X[10] ^= ROTL_32(X[6] + X[2], 18);   \
		X[3] ^= ROTL_32(X[15] + X[11], 7);   \
		X[7] ^= ROTL_32(X[3] + X[15], 9);    \
		X[11] ^= ROTL_32(X[7] + X[3], 13);   \
		X[15] ^= ROTL_32(X[11] + X[7], 18);  \
		X[1] ^= ROTL_32(X[0] + X[3], 7);     \
		X[2] ^= ROTL_32(X[1] + X[0], 9);     \
		X[3] ^= ROTL_32(X[2] + X[1], 13);    \
		X[0] ^= ROTL_32(X[3] + X[2], 18);    \
		X[6] ^= ROTL_32(X[5] + X[4], 7);     \
		X[7] ^= ROTL_32(X[6] + X[5], 9);     \
		X[4] ^= ROTL_32(X[7] + X[6], 13);    \
		X[5] ^= ROTL_32(X[4] + X[7], 18);    \
		X[11] ^= ROTL_32(X[10] + X[9], 7);   \
		X[8] ^= ROTL_32(X[11] + X[10], 9);   \
		X[9] ^= ROTL_32(X[8] + X[11], 13);   \
		X[10] ^= ROTL_32(X[9] + X[8], 18);   \
		X[12] ^= ROTL_32(X[15] + X[14], 7);  \
		X[13] ^= ROTL_32(X[12] + X[15], 9);  \
		X[14] ^= ROTL_32(X[13] + X[12], 13); \
		X[15] ^= ROTL_32(X[14] + X[13], 18); \
	}

static void salsa20_block(uint32_t block[SALSA20_BLOCK_WORDS])
{
	uint32_t temp[SALSA20_BLOCK_WORDS];

	memcpy(temp, block, sizeof(uint32_t) * SALSA20_BLOCK_WORDS);

	// Iterate 4 times.
	SALSA20_ROUND(temp);
	SALSA20_ROUND(temp);
	SALSA20_ROUND(temp);
	SALSA20_ROUND(temp);

	block[0] += temp[0];
	block[1] += temp[1];
	block[2] += temp[2];
	block[3] += temp[3];
	block[4] += temp[4];
	block[5] += temp[5];
	block[6] += temp[6];
	block[7] += temp[7];
	block[8] += temp[8];
	block[9] += temp[9];
	block[10] += temp[10];
	block[11] += temp[11];
	block[12] += temp[12];
	block[13] += temp[13];
	block[14] += temp[14];
	block[15] += temp[15];
}

static void scrypt_block_mix(byte_t *in_blocks, byte_t *out_blocks, uint32_t count)
{
	byte_t t[64];
	byte_t *x = in_blocks + ((count - 1) * 64);
	byte_t *y = out_blocks;

	for (uint32_t i = 0; i < count; ++i)
	{
		for (uint32_t j = 0; j < 64; ++j)
		{
			t[j] = x[j] ^ in_blocks[(i * 64) + j];
		}

		salsa20_block((void *)t);

		// Even blocks followed by odd blocks.
		if (i % 2 == 0)
		{
			memcpy(y + ((i / 2) * 64), t, 64);
		}
		else
		{
			memcpy(y + (count / 2 * 64) + ((i / 2) * 64), t, 64);
		}
	}
}

static int32_t scrypt_rom_mix(byte_t *in_blocks, byte_t *out_blocks, uint32_t size, uint32_t shift)
{
	byte_t *temp = NULL;
	byte_t *x = NULL;
	byte_t *y = NULL;
	byte_t *t = NULL;
	size_t temp_size = size * (1ull << shift) + size + size;

	uint32_t count = size / 64;

	temp = malloc(temp_size);

	if (temp == NULL)
	{
		return -1;
	}

	memset(temp, 0, temp_size);

	x = temp + size * (1ull << shift);
	memcpy(x, in_blocks, size);

	y = x + size;

	for (uint32_t i = 0; i < (1ull << shift); ++i)
	{
		memcpy(temp + (i * size), x, size);
		scrypt_block_mix(x, y, count);

		// Swap x,y
		t = x;
		x = y;
		y = t;
	}

	for (uint32_t i = 0; i < (1ull << shift); ++i)
	{
		uint32_t j = *((uint32_t *)x) % (1ull << shift);

		for (uint32_t k = 0; k < size; ++k)
		{
			y[k] = x[k] ^ temp[(j * size) + k];
		}

		scrypt_block_mix(y, x, count);
	}

	memcpy(out_blocks, x, size);

	free(temp);

	return 0;
}

uint32_t scrypt(void *password, size_t password_size, void *salt, size_t salt_size, uint32_t n, uint32_t p, uint32_t r, void *key,
				size_t key_size)
{
	uint32_t result = 0;

	byte_t *blocks = NULL;
	size_t total_size = r * p * 128;
	size_t block_size = r * 128;

	blocks = malloc(total_size);

	if (blocks == NULL)
	{
		return 0;
	}

	result = pbkdf2(HMAC_SHA256, password, password_size, salt, salt_size, 1, blocks, total_size);

	if (result == 0)
	{
		free(blocks);
		return 0;
	}

	for (uint32_t i = 0; i < p; ++i)
	{
		scrypt_rom_mix(blocks + (i * block_size), blocks + (i * block_size), block_size, n);
	}

	result = pbkdf2(HMAC_SHA256, password, password_size, blocks, total_size, 1, key, key_size);

	free(blocks);

	return result;
}
