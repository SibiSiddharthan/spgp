/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <scrypt.h>
#include <pbkdf2.h>
#include <hmac.h>
#include <byteswap.h>
#include <minmax.h>
#include <rotate.h>
#include <round.h>

// Refer RFC 7914 : The scrypt Password-Based Key Derivation Function

#define SALSA20_BLOCK_WORDS 16

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
	byte_t x[64];
	byte_t *y = out_blocks;

	// Copy the last block
	memcpy(x, in_blocks + ((count - 1) * 64), 64);

	for (uint32_t i = 0; i < count; ++i)
	{
		for (uint32_t j = 0; j < 64; ++j)
		{
			x[j] = x[j] ^ in_blocks[(i * 64) + j];
		}

		salsa20_block((void *)x);

		// Even blocks followed by odd blocks.
		if (i % 2 == 0)
		{
			memcpy(y + ((i / 2) * 64), x, 64);
		}
		else
		{
			memcpy(y + ((count / 2) * 64) + ((i / 2) * 64), x, 64);
		}
	}
}

static void scrypt_rom_mix(void *temp, byte_t *in_blocks, byte_t *out_blocks, uint32_t size, uint32_t cost)
{
	byte_t *v = NULL;
	byte_t *x = NULL;
	byte_t *y = NULL;

	size_t v_size = size * cost;
	size_t x_size = size;
	size_t y_size = size;
	size_t temp_size = v_size + x_size + y_size;

	uint32_t count = size / 64;

	memset(temp, 0, temp_size);

	v = temp;
	x = v + v_size;
	y = x + x_size;

	memcpy(x, in_blocks, size);

	for (uint32_t i = 0; i < cost; ++i)
	{
		byte_t *t = NULL;

		memcpy(v + (i * size), x, size);
		scrypt_block_mix(x, y, count);

		// Swap x,y
		t = x;
		x = y;
		y = t;
	}

	for (uint32_t i = 0; i < cost; ++i)
	{
		uint32_t j = *((uint32_t *)(x + ((count - 1) * 64))) % cost;

		for (uint32_t k = 0; k < size; ++k)
		{
			y[k] = x[k] ^ v[(j * size) + k];
		}

		scrypt_block_mix(y, x, count);
	}

	memcpy(out_blocks, x, size);
}

uint32_t scrypt(void *password, size_t password_size, void *salt, size_t salt_size, uint32_t cost, uint32_t block, uint32_t parallel,
				void *key, size_t key_size)
{
	uint32_t result = 0;

	byte_t *blocks = NULL;
	byte_t *rom = NULL;
	size_t pbkdf2_size = block * parallel * 128;
	size_t block_size = block * 128;
	size_t rom_size = (block_size * cost) + (2 * block_size);
	size_t total_size = pbkdf2_size + rom_size;

	blocks = malloc(total_size);
	rom = blocks + pbkdf2_size;

	if (blocks == NULL)
	{
		return 0;
	}

	pbkdf2(HASH_SHA256, password, password_size, salt, salt_size, 1, blocks, pbkdf2_size);

	for (uint32_t i = 0; i < parallel; ++i)
	{
		scrypt_rom_mix(rom, blocks + (i * block_size), blocks + (i * block_size), block_size, cost);
	}

	result = pbkdf2(HASH_SHA256, password, password_size, blocks, pbkdf2_size, 1, key, key_size);

	free(blocks);

	return result;
}
