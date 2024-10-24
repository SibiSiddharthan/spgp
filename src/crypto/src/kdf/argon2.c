/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <argon2.h>
#include <blake2.h>
#include <byteswap.h>
#include <minmax.h>
#include <rotate.h>
#include <round.h>

// Refer RFC 9106 : Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications

#define ARGON2_D  0
#define ARGON2_I  1
#define ARGON2_ID 2
#define ARGON2_DS 4

#define ARGON2_BLOCK_SIZE 1024

static void H(byte_t *input, uint32_t input_size, byte_t *output, uint32_t output_size)
{
	blake2b_param bparam = {0};
	blake2b_ctx bctx;

	if (output_size <= 64)
	{
		bparam.digest_size = output_size;
		bparam.key_size = 0;
		bparam.depth = 1;
		bparam.fanout = 1;

		blake2b_init(&bctx, sizeof(blake2b_ctx), &bparam, NULL);

		blake2b_update(&bctx, &output_size, 4);
		blake2b_update(&bctx, input, input_size);

		blake2b_final(&bctx, output, output_size);
	}
	else
	{
		byte_t h[64];
		uint32_t pos = 0;
		uint32_t r = CEIL_DIV(output_size, 32) - 2;

		bparam.digest_size = 64;
		bparam.key_size = 0;
		bparam.depth = 1;
		bparam.fanout = 1;

		// First iteration
		blake2b_init(&bctx, sizeof(blake2b_ctx), &bparam, NULL);

		blake2b_update(&bctx, &output_size, 4);
		blake2b_update(&bctx, input, input_size);

		blake2b_final(&bctx, h, 64);

		memcpy(output, h, 32);
		pos += 32;

		for (uint32_t i = 1; i < r; ++i)
		{
			blake2b_init(&bctx, sizeof(blake2b_ctx), &bparam, NULL);
			blake2b_update(&bctx, h, 64);
			blake2b_final(&bctx, h, 64);

			memcpy(output + pos, h, 32);
			pos += 32;
		}

		// Last iteration
		bparam.digest_size = output_size - (32 * r);

		blake2b_init(&bctx, sizeof(blake2b_ctx), &bparam, NULL);
		blake2b_update(&bctx, h, 64);
		blake2b_final(&bctx, h, bparam.digest_size);

		memcpy(output + pos, h, bparam.digest_size);
	}
}

#define GB(A, B, C, D)                                      \
	{                                                       \
		A = A + B + (2ull * ((uint32_t)A) * ((uint32_t)B)); \
		D = ROTR_64(D ^ A, 32);                             \
		C = C + D + (2ull * ((uint32_t)C) * ((uint32_t)D)); \
		B = ROTR_64(B ^ C, 24);                             \
                                                            \
		A = A + B + (2ull * ((uint32_t)A) * ((uint32_t)B)); \
		D = ROTR_64(D ^ A, 16);                             \
		C = C + D + (2ull * ((uint32_t)C) * ((uint32_t)D)); \
		B = ROTR_64(B ^ C, 63);                             \
	}

#define P(V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15) \
	{                                                                           \
		GB(V0, V4, V8, V12);                                                    \
		GB(V1, V5, V9, V13);                                                    \
		GB(V2, V6, V10, V14);                                                   \
		GB(V3, V7, V11, V15);                                                   \
                                                                                \
		GB(V0, V5, V10, V15);                                                   \
		GB(V1, V6, V11, V12);                                                   \
		GB(V2, V7, V8, V13);                                                    \
		GB(V3, V4, V9, V14);                                                    \
	}

static void G(byte_t o[ARGON2_BLOCK_SIZE], byte_t b1[ARGON2_BLOCK_SIZE], byte_t b2[ARGON2_BLOCK_SIZE], uint64_t sbox[ARGON2_BLOCK_SIZE])
{
	byte_t r[ARGON2_BLOCK_SIZE];
	byte_t p[ARGON2_BLOCK_SIZE];

	uint64_t *x = (uint64_t *)p;
	uint64_t w = 0;

	// Initial XOR
	for (uint32_t i = 0; i < 1024; ++i)
	{
		r[i] = b1[i] ^ b2[i];
	}

	memcpy(p, r, ARGON2_BLOCK_SIZE);

	if (sbox != NULL)
	{
		// XOR first and last qword.
		w = x[0] ^ x[127];

		// Repeat 96 times.
		for (uint32_t i = 0; i < 96; ++i)
		{
			uint32_t wh = w >> 32;
			uint32_t wl = w & 0xFFFFFFFF;
			uint64_t y = sbox[(wh & 0x1FF)];
			uint64_t z = sbox[512 + (wl & 0x1FF)];

			w = (uint64_t)wh * (uint64_t)wl;
			w += y;
			w ^= z;
		}
	}

	// Row wise permutation
	P(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]);
	P(x[16], x[17], x[18], x[19], x[20], x[21], x[22], x[23], x[24], x[25], x[26], x[27], x[28], x[29], x[30], x[31]);
	P(x[32], x[33], x[34], x[35], x[36], x[37], x[38], x[39], x[40], x[41], x[42], x[43], x[44], x[45], x[46], x[47]);
	P(x[48], x[49], x[50], x[51], x[52], x[53], x[54], x[55], x[56], x[57], x[58], x[59], x[60], x[61], x[62], x[63]);
	P(x[64], x[65], x[66], x[67], x[68], x[69], x[70], x[71], x[72], x[73], x[74], x[75], x[76], x[77], x[78], x[79]);
	P(x[80], x[81], x[82], x[83], x[84], x[85], x[86], x[87], x[88], x[89], x[90], x[91], x[92], x[93], x[94], x[95]);
	P(x[96], x[97], x[98], x[99], x[100], x[101], x[102], x[103], x[104], x[105], x[106], x[107], x[108], x[109], x[110], x[111]);
	P(x[112], x[113], x[114], x[115], x[116], x[117], x[118], x[119], x[120], x[121], x[122], x[123], x[124], x[125], x[126], x[127]);

	// Column wise permutation
	P(x[0], x[1], x[16], x[17], x[32], x[33], x[48], x[49], x[64], x[65], x[80], x[81], x[96], x[97], x[112], x[113]);
	P(x[2], x[3], x[18], x[19], x[34], x[35], x[50], x[51], x[66], x[67], x[82], x[83], x[98], x[99], x[114], x[115]);
	P(x[4], x[5], x[20], x[21], x[36], x[37], x[52], x[53], x[68], x[69], x[84], x[85], x[100], x[101], x[116], x[117]);
	P(x[6], x[7], x[22], x[23], x[38], x[39], x[54], x[55], x[70], x[71], x[86], x[87], x[102], x[103], x[118], x[119]);
	P(x[8], x[9], x[24], x[25], x[40], x[41], x[56], x[57], x[72], x[73], x[88], x[89], x[104], x[105], x[120], x[121]);
	P(x[10], x[11], x[26], x[27], x[42], x[43], x[58], x[59], x[74], x[75], x[90], x[91], x[106], x[107], x[122], x[123]);
	P(x[12], x[13], x[28], x[29], x[44], x[45], x[60], x[61], x[76], x[77], x[92], x[93], x[108], x[109], x[124], x[125]);
	P(x[14], x[15], x[30], x[31], x[46], x[47], x[62], x[63], x[78], x[79], x[94], x[95], x[110], x[111], x[126], x[127]);

	// Final XOR
	for (uint32_t i = 0; i < 1024; ++i)
	{
		o[i] = r[i] ^ p[i];
	}

	if (sbox != NULL)
	{
		x = (uint64_t *)o;

		x[0] += w;
		x[127] += w;
	}
}

static void generate_sbox(byte_t sbox[ARGON2_BLOCK_SIZE * 8], byte_t first_block[ARGON2_BLOCK_SIZE])
{
	byte_t zero_block[ARGON2_BLOCK_SIZE] = {0};
	byte_t out_block[ARGON2_BLOCK_SIZE];

	size_t pos = 0;

	for (uint32_t i = 0; i < 8; ++i)
	{
		G(out_block, zero_block, first_block, NULL);
		G(out_block, zero_block, out_block, NULL);

		memcpy(sbox + pos, out_block, ARGON2_BLOCK_SIZE);
		pos += ARGON2_BLOCK_SIZE;
	}
}

static void block_offset(uint32_t argon2_type, uint32_t i, uint32_t j, uint32_t lanes, uint32_t columns, uint32_t pass, uint32_t *l,
						 uint32_t *z)
{
	uint32_t j1, j2;
	uint32_t w;
	uint32_t x, y, zz;

	uint32_t slice = j / (columns / 4);

	if (argon2_type == ARGON2_D || argon2_type == ARGON2_DS || (argon2_type == ARGON2_ID && !(pass == 0 && slice < 2)))
	{
	}

	x = j1 >> 31;
	y = w * x;
	zz = w - 1 - y;
}

static uint32_t argon2_common(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
							  uint32_t iterations, uint32_t argon2_type, void *secret, uint32_t secret_size, void *data, uint32_t data_size,
							  void *key, uint32_t key_size)
{
	blake2b_param bparam = BLAKE2_PARAM_INIT(64, 0);
	blake2b_ctx bctx;

	byte_t h0[72];
	uint32_t version = 0x13;

	byte_t *blocks = NULL;
	byte_t *sbox = NULL;
	size_t sbox_size = argon2_type == ARGON2_DS ? (ARGON2_BLOCK_SIZE * 8) : 0;
	size_t blocks_size = 4 * parallel * (memory / (4 * parallel)) * ARGON2_BLOCK_SIZE;
	size_t total_size = sbox_size + blocks_size;

	uint32_t lanes = parallel;
	uint32_t columns = blocks_size / (parallel * ARGON2_BLOCK_SIZE);

	size_t lane_size = blocks_size / parallel;

	if (memory < (8 * parallel))
	{
		return 0;
	}

	blocks = malloc(total_size);

	if (blocks == NULL)
	{
		return 0;
	}

	// Generate H0
	blake2b_init(&bctx, sizeof(blake2b_ctx), &bparam, NULL);

	blake2b_update(&bctx, &parallel, 4);
	blake2b_update(&bctx, &key_size, 4);
	blake2b_update(&bctx, &memory, 4);
	blake2b_update(&bctx, &iterations, 4);
	blake2b_update(&bctx, &version, 4);
	blake2b_update(&bctx, &argon2_type, 4);
	blake2b_update(&bctx, &password_size, 4);
	blake2b_update(&bctx, password, password_size);
	blake2b_update(&bctx, &salt_size, 4);
	blake2b_update(&bctx, salt, salt_size);

	blake2b_update(&bctx, &secret_size, 4);
	if (secret_size > 0)
	{
		blake2b_update(&bctx, secret, secret_size);
	}

	blake2b_update(&bctx, &data_size, 4);
	if (data_size > 0)
	{
		blake2b_update(&bctx, data, data_size);
	}

	blake2b_final(&bctx, h0, 64);

	uint32_t *x = (uint32_t *)&h0[64];
	uint32_t *y = (uint32_t *)&h0[68];

	// Calculate B[i][0]
	for (uint32_t i = 0; i < lanes; ++i)
	{
		*x = 0;
		*y = i;

		H(h0, 72, blocks + (i * lane_size), ARGON2_BLOCK_SIZE);
	}

	// Calculate B[i][1]
	for (uint32_t i = 0; i < lanes; ++i)
	{
		*x = 1;
		*y = i;

		H(h0, 72, blocks + (i * lane_size) + ARGON2_BLOCK_SIZE, ARGON2_BLOCK_SIZE);
	}

	// First iteration
	if (argon2_type == ARGON2_DS)
	{
		sbox = blocks + blocks_size;
		generate_sbox(sbox, blocks);
	}

	// Calculate B[i][j]
	for (uint32_t j = 2; j < columns; ++j)
	{
		for (uint32_t i = 0; i < lanes; ++i)
		{
			uint32_t l, z;

			// block_offset(argon2_type, i, j, &l, &z);
			G(blocks + (i * lane_size) + (j * ARGON2_BLOCK_SIZE), blocks + (i * lane_size) + ((j - 1) * ARGON2_BLOCK_SIZE),
			  blocks + (l * lane_size) + (z * ARGON2_BLOCK_SIZE), (uint64_t *)sbox);
		}
	}

	// More iterations
	for (uint32_t k = 1; k < iterations; ++k)
	{
		byte_t temp[1024];

		if (argon2_type == ARGON2_DS)
		{
			generate_sbox(sbox, blocks);
		}

		// Calculate B[i][0]
		for (uint32_t i = 0; i < lanes; ++i)
		{
			uint32_t l, z;

			// block_offset(argon2_type, i, 0, &l, &z);
			G(temp, blocks + (i * lane_size) + ((columns - 1) * ARGON2_BLOCK_SIZE), blocks + (l * lane_size) + (z * ARGON2_BLOCK_SIZE),
			  (uint64_t *)sbox);

			for (uint32_t w = 0; w < 1024; ++w)
			{
				*(blocks + (i * lane_size) + w) ^= temp[w];
			}
		}

		// Calculate B[i][j]
		for (uint32_t j = 1; j < columns; ++j)
		{
			for (uint32_t i = 0; i < lanes; ++i)
			{
				uint32_t l, z;

				// block_offset(argon2_type, i, j, &l, &z);
				G(temp, blocks + (i * lane_size) + ((j - 1) * ARGON2_BLOCK_SIZE), blocks + (l * lane_size) + (z * ARGON2_BLOCK_SIZE),
				  (uint64_t *)sbox);

				for (uint32_t w = 0; w < 1024; ++w)
				{
					*(blocks + (i * lane_size) + (j * ARGON2_BLOCK_SIZE) + w) ^= temp[w];
				}
			}
		}
	}

	// Calculate C
	byte_t c[1024] = {0};

	for (uint32_t i = 0; i < lanes; ++i)
	{
		for (uint32_t w = 0; w < 1024; ++w)
		{
			c[w] ^= *(blocks + (i * lane_size) + ((columns - 1) * ARGON2_BLOCK_SIZE) + w);
		}
	}

	// Calculate T
	H(c, 1024, key, key_size);

	free(blocks);

	return key_size;
}

uint32_t argon2d(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
				 uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size)
{
	return argon2_common(password, password_size, salt, salt_size, parallel, memory, iterations, ARGON2_D, secret, secret_size, data,
						 data_size, key, key_size);
}

uint32_t argon2i(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
				 uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size)
{
	return argon2_common(password, password_size, salt, salt_size, parallel, memory, iterations, ARGON2_I, secret, secret_size, data,
						 data_size, key, key_size);
}

uint32_t argon2id(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
				  uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size)
{
	return argon2_common(password, password_size, salt, salt_size, parallel, memory, iterations, ARGON2_ID, secret, secret_size, data,
						 data_size, key, key_size);
}

uint32_t argon2ds(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
				  uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size)
{
	return argon2_common(password, password_size, salt, salt_size, parallel, memory, iterations, ARGON2_DS, secret, secret_size, data,
						 data_size, key, key_size);
}
