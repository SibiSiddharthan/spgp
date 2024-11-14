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
#include <ptr.h>
#include <rotate.h>
#include <round.h>

// Refer RFC 9106 : Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications

#define ARGON2_D  0
#define ARGON2_I  1
#define ARGON2_ID 2
#define ARGON2_DS 4

#define ARGON2_VERSION     0x13
#define ARGON2_SLICE_COUNT 4
#define ARGON2_BLOCK_SIZE  1024

#define ARGON2_BLOCK(A, X, Y) (PTR_OFFSET((A)->blocks, (((X) * ((A)->columns)) + (Y)) * ARGON2_BLOCK_SIZE))

typedef struct _argon2_ctx
{
	uint32_t version;
	uint32_t argon2_type;
	uint32_t parallel;
	uint32_t memory;
	uint32_t iterations;
	uint32_t key_size;

	byte_t h0[72];
	uint32_t lanes;
	uint32_t columns;
	uint32_t blocks_in_segment;
	uint32_t blocks_in_lane;
	uint32_t total_blocks;

	struct
	{
		uint32_t start;
		uint32_t end;
	} slices[ARGON2_SLICE_COUNT];

	size_t total_size;

	void *blocks;
	void *sbox;
} argon2_ctx;

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

		// BLAKE2B(LE32(T) || A)
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

		// Copy only the first 32 bytes
		memcpy(output, h, 32);
		pos += 32;

		// Other iterations
		for (uint32_t i = 1; i < r; ++i)
		{
			blake2b_init(&bctx, sizeof(blake2b_ctx), &bparam, NULL);
			blake2b_update(&bctx, h, 64);
			blake2b_final(&bctx, h, 64);

			// Copy only the first 32 bytes
			memcpy(output + pos, h, 32);
			pos += 32;
		}

		// Last iteration
		bparam.digest_size = output_size - (32 * r);

		blake2b_init(&bctx, sizeof(blake2b_ctx), &bparam, NULL);
		blake2b_update(&bctx, h, 64);
		blake2b_final(&bctx, h, bparam.digest_size);

		// Copy all of the truncated digest
		memcpy(output + pos, h, bparam.digest_size);
	}
}

static inline void X(byte_t r[ARGON2_BLOCK_SIZE], byte_t a[ARGON2_BLOCK_SIZE], byte_t b[ARGON2_BLOCK_SIZE])
{
	for (uint32_t i = 0; i < ARGON2_BLOCK_SIZE; ++i)
	{
		r[i] = a[i] ^ b[i];
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
	X(r, b1, b2);

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
	X(o, r, p);

	if (sbox != NULL)
	{
		x = (uint64_t *)o;

		x[0] += w;
		x[127] += w;
	}
}

static argon2_ctx *argon2_new(uint32_t argon2_type, uint32_t parallel, uint32_t memory, uint32_t iterations, uint32_t key_size)
{
	argon2_ctx *actx = NULL;

	size_t sbox_size = argon2_type == ARGON2_DS ? (ARGON2_BLOCK_SIZE * 8) : 0;
	size_t blocks_size = ROUND_DOWN(memory, 4 * parallel) * ARGON2_BLOCK_SIZE;
	size_t total_size = sbox_size + blocks_size + ROUND_UP(sizeof(argon2_ctx), ARGON2_BLOCK_SIZE);

	uint32_t columns = blocks_size / (parallel * ARGON2_BLOCK_SIZE);

	// Paramter validation
	if (key_size < 4)
	{
		return 0;
	}

	if (parallel < 1 || parallel >= (1ull << 24))
	{
		return 0;
	}

	if (memory < (4 * parallel))
	{
		return 0;
	}

	if (iterations < 0)
	{
		return 0;
	}

	actx = malloc(total_size);

	if (actx == NULL)
	{
		return 0;
	}

	memset(actx, 0, total_size);

	// Set the parameters
	actx->version = ARGON2_VERSION;
	actx->argon2_type = argon2_type;
	actx->parallel = parallel;
	actx->memory = memory;
	actx->iterations = iterations;
	actx->key_size = key_size;

	actx->lanes = parallel;
	actx->columns = blocks_size / (parallel * ARGON2_BLOCK_SIZE);
	actx->blocks_in_segment = columns / 4;
	actx->blocks_in_lane = columns;
	actx->total_blocks = actx->lanes * actx->columns;

	// Set the slices
	actx->slices[0].start = 0;
	actx->slices[0].end = actx->columns / 4;

	actx->slices[1].start = actx->columns / 4;
	actx->slices[1].end = actx->columns / 2;

	actx->slices[2].start = actx->columns / 2;
	actx->slices[2].end = 3 * (actx->columns / 4);

	actx->slices[3].start = 3 * (actx->columns / 4);
	actx->slices[3].end = actx->columns;

	actx->total_size = total_size;

	actx->blocks = PTR_OFFSET(actx, ROUND_UP(sizeof(argon2_ctx), ARGON2_BLOCK_SIZE));

	if (argon2_type == ARGON2_DS)
	{
		actx->sbox = PTR_OFFSET(actx->blocks, blocks_size);
	}

	return actx;
}

void argon2_delete(argon2_ctx *actx)
{
	memset(actx, 0, actx->total_size);
	free(actx);
}

static void argon2_generate_sbox(argon2_ctx *actx)
{
	byte_t zero_block[ARGON2_BLOCK_SIZE] = {0};
	byte_t out_block[ARGON2_BLOCK_SIZE];

	byte_t *first_block = actx->blocks;

	size_t pos = 0;

	for (uint32_t i = 0; i < 8; ++i)
	{
		G(out_block, zero_block, first_block, NULL);
		G(out_block, zero_block, out_block, NULL);

		memcpy(PTR_OFFSET(actx->sbox, pos), out_block, ARGON2_BLOCK_SIZE);
		pos += ARGON2_BLOCK_SIZE;
	}
}

static void argon2_generate_addresses(argon2_ctx *actx, byte_t address_block[ARGON2_BLOCK_SIZE], uint32_t pass, uint32_t lane,
									  uint32_t slice, uint32_t counter)
{
	byte_t zero_block[ARGON2_BLOCK_SIZE] = {0};
	byte_t input_block[ARGON2_BLOCK_SIZE] = {0};
	byte_t out_block[ARGON2_BLOCK_SIZE];

	uint64_t *p = (uint64_t *)input_block;

	p[0] = (uint64_t)pass;
	p[1] = (uint64_t)lane;
	p[2] = (uint64_t)slice;
	p[3] = (uint64_t)actx->total_blocks;
	p[4] = (uint64_t)actx->iterations;
	p[5] = (uint64_t)actx->argon2_type;
	p[6] = (uint64_t)counter;

	G(out_block, zero_block, input_block, NULL);
	G(address_block, zero_block, out_block, NULL);
}

static uint64_t argon2_block_offset(argon2_ctx *actx, uint32_t pass, uint32_t slice, uint32_t lane, uint32_t column, uint64_t psuedo_rand)
{
	uint32_t j1, j2;
	uint32_t ref_lane, ref_index;

	uint64_t block_count;
	uint64_t x, y, zz;

	byte_t same_lane = 0;

	uint64_t block_start = 0;
	uint64_t block_offset = 0;

	j1 = psuedo_rand & 0xFFFFFFFF;
	j2 = (psuedo_rand >> 32) % actx->lanes;

	ref_lane = j2;

	/*
		This is pretty complicated. The argon2 paper calls this algorithm index alpha.
		We need to find the count of blocks to be considered for indexing.
		Here is my explanation of it.

		First up if we are dealing with the first pass and first slice we consider the current lane only.

		We have 2 conditions if ref_lane is the current lane or not.
		If (ref_lane == lane) we need to count all the blocks in the current lane
		that have been filled excluding the last filled block.

		For the first pass this is always the current column index - 1.
		Consider N columns indexed [0, N-1]. The columns before Ci is i.
		We exclude the last filled block, so block_count -> i - 1

		For subsequent passes, we have already filled the other blocks.
		We need to consider all the other blocks in the other segments(i.e 3 segments excluding this one) belonging to this lane
		except this one.
		From this segment consider only filled blocks.
		From the above total exclude the last filled block.

		If (ref_lane != lane) we need to count all the blocks in the current lane and not in
		the same slice that have been filled.
		If the block in consideration is the first block of the segment we exclude the last block counted

		For the first pass the block count is always the number of slices completed multiplied by the blocks in each segment.
		For subsequent passes, consider all blocks in the lane not in the current segment.
		Now apply the first block in segment condition to get the count.
	*/

	if (pass == 0 && slice == 0)
	{
		ref_lane = lane;
	}

	if (ref_lane == lane)
	{
		same_lane = 1;
	}

	if (pass == 0)
	{
		if (same_lane)
		{
			block_count = column - 1;
		}
		else
		{
			block_count = slice * actx->blocks_in_segment;

			if (column - actx->slices[slice].start == 0)
			{
				block_count -= 1;
			}
		}
	}
	else
	{
		if (same_lane)
		{
			block_count = actx->columns - actx->blocks_in_segment + (column % actx->blocks_in_segment) - 1;
		}
		else
		{
			block_count = actx->columns - actx->blocks_in_segment;

			if (column - actx->slices[slice].start == 0)
			{
				block_count -= 1;
			}
		}
	}

	/*
		We now have our block count. We use it to get the ref index.
		This is the approximation function used.
	*/
	x = ((uint64_t)j1 * (uint64_t)j1) >> 32;
	y = (block_count * x) >> 32;
	zz = block_count - 1 - y;

	ref_index = zz;

	/*
		The blocks are counted from oldest to newest.
		Say we are at (pass = 1, slice = 1). The blocks are counted from slice 2. (ie S2 , S3, S1).
		Do modular arithmentic to deal with it.

		BLOCK[ref_lane][(block_start + ref_index) % actx->columns] will be the desired block.
	*/

	if (pass != 0)
	{
		block_start = (slice == (ARGON2_SLICE_COUNT - 1)) ? 0 : ((slice + 1) * actx->blocks_in_segment);
	}

	block_offset = (block_start + ref_index) % actx->columns;
	block_offset += ref_lane * actx->columns;
	block_offset *= ARGON2_BLOCK_SIZE;

	return block_offset;
}

static void argon2_generate_h0(argon2_ctx *actx, void *password, uint32_t password_size, void *salt, uint32_t salt_size, void *secret,
							   uint32_t secret_size, void *data, uint32_t data_size)
{
	blake2b_param bparam = BLAKE2_PARAM_INIT(64, 0);
	blake2b_ctx bctx;

	blake2b_init(&bctx, sizeof(blake2b_ctx), &bparam, NULL);

	blake2b_update(&bctx, &actx->parallel, 4);
	blake2b_update(&bctx, &actx->key_size, 4);
	blake2b_update(&bctx, &actx->memory, 4);
	blake2b_update(&bctx, &actx->iterations, 4);
	blake2b_update(&bctx, &actx->version, 4);
	blake2b_update(&bctx, &actx->argon2_type, 4);
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

	blake2b_final(&bctx, actx->h0, 64);
}

static void argon2_intial_fill(argon2_ctx *actx)
{
	// We have an extra 8 bytes in h0 just for this.
	// This makes H() way simpler.
	uint32_t *x = (uint32_t *)&actx->h0[64];
	uint32_t *y = (uint32_t *)&actx->h0[68];

	// Calculate B[i][0]
	*x = 0;

	for (uint32_t i = 0; i < actx->lanes; ++i)
	{
		*y = i;
		H(actx->h0, 72, ARGON2_BLOCK(actx, i, 0), ARGON2_BLOCK_SIZE);
	}

	// Calculate B[i][1]
	*x = 1;

	for (uint32_t i = 0; i < actx->lanes; ++i)
	{
		*y = i;
		H(actx->h0, 72, ARGON2_BLOCK(actx, i, 1), ARGON2_BLOCK_SIZE);
	}
}

static void argon2_fill_segment(argon2_ctx *actx, uint32_t pass, uint32_t slice, uint32_t lane)
{
	byte_t addresses[ARGON2_BLOCK_SIZE];
	byte_t temp[ARGON2_BLOCK_SIZE];

	uint32_t segment_counter = 1;
	uint32_t block_counter = 0;

	uint64_t psuedo_rand = 0; // J1 || J2

	byte_t data_dependent_addressing = 0;

	if (actx->argon2_type == ARGON2_D || actx->argon2_type == ARGON2_DS || (actx->argon2_type == ARGON2_ID && !(pass == 0 && slice < 2)))
	{
		data_dependent_addressing = 1;
	}

	// Calculate B[i][j > 2]
	for (uint32_t j = actx->slices[slice].start; j < actx->slices[slice].end; ++j, ++block_counter)
	{
		// Skip first 2 B[i][0], B[i][1]
		if (pass == 0)
		{
			if ((j == 0) && (actx->slices[slice].end > 2) && (data_dependent_addressing == 0))
			{
				// Generate new addresses for segments in the first slice if we are going to need them.
				argon2_generate_addresses(actx, addresses, pass, lane, slice, segment_counter);
				++segment_counter;
			}

			if (j < 2)
			{
				continue;
			}
		}

		// Calculate J1, J2
		if (data_dependent_addressing)
		{
			// The first 8 bytes of the previous block
			psuedo_rand = *(uint64_t *)ARGON2_BLOCK(actx, lane, j != 0 ? j - 1 : actx->columns - 1);
		}
		else
		{
			// Generate new addresses if we need them.
			// Upto 128 blocks in a segment can use the same address block. More than that we need to generate a new one.
			if (block_counter % 128 == 0)
			{
				argon2_generate_addresses(actx, addresses, pass, lane, slice, segment_counter);
				++segment_counter;
			}

			// The first 8 bytes of the block given by the counter.
			psuedo_rand = *(uint64_t *)PTR_OFFSET(addresses, (8 * block_counter) % ARGON2_BLOCK_SIZE);
		}

		// First pass
		if (pass == 0)
		{
			G(ARGON2_BLOCK(actx, lane, j), ARGON2_BLOCK(actx, lane, j - 1),
			  PTR_OFFSET(actx->blocks, argon2_block_offset(actx, pass, slice, lane, j, psuedo_rand)), actx->sbox);
		}
		// Later passes
		else
		{
			// Calculate B[i][0]
			if (j == 0)
			{
				G(temp, ARGON2_BLOCK(actx, lane, actx->columns - 1),
				  PTR_OFFSET(actx->blocks, argon2_block_offset(actx, pass, slice, lane, j, psuedo_rand)), actx->sbox);
				X(ARGON2_BLOCK(actx, lane, 0), ARGON2_BLOCK(actx, lane, 0), temp);
			}
			// Calculate B[i][j > 1]
			else
			{

				G(temp, ARGON2_BLOCK(actx, lane, j - 1),
				  PTR_OFFSET(actx->blocks, argon2_block_offset(actx, pass, slice, lane, j, psuedo_rand)), actx->sbox);
				X(ARGON2_BLOCK(actx, lane, j), ARGON2_BLOCK(actx, lane, j), temp);
			}
		}
	}
}

static void argon2_fill_segments(argon2_ctx *actx)
{
	for (uint32_t k = 0; k < actx->iterations; ++k)
	{
		// Generate sbox if required
		if (actx->argon2_type == ARGON2_DS)
		{
			argon2_generate_sbox(actx);
		}

		// Fill the segments slicewise
		for (uint32_t s = 0; s < ARGON2_SLICE_COUNT; ++s)
		{
			for (uint32_t i = 0; i < actx->lanes; ++i)
			{
				argon2_fill_segment(actx, k, s, i);
			}
		}
	}
}

static void argon2_final(argon2_ctx *actx, void *key, uint32_t key_size)
{
	// Calculate C
	byte_t c[ARGON2_BLOCK_SIZE] = {0};

	for (uint32_t i = 0; i < actx->lanes; ++i)
	{
		X(c, c, ARGON2_BLOCK(actx, i, actx->columns - 1));
	}

	// Calculate T
	H(c, ARGON2_BLOCK_SIZE, key, key_size);
}

static uint32_t argon2_common(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
							  uint32_t iterations, uint32_t argon2_type, void *secret, uint32_t secret_size, void *data, uint32_t data_size,
							  void *key, uint32_t key_size)
{
	argon2_ctx *actx = NULL;

	// Create the context
	actx = argon2_new(argon2_type, parallel, memory, iterations, key_size);

	// Generate H0
	argon2_generate_h0(actx, password, password_size, salt, salt_size, secret, secret_size, data, data_size);

	// First blocks
	argon2_intial_fill(actx);

	// File segments
	argon2_fill_segments(actx);

	// Output the key
	argon2_final(actx, key, key_size);

	// Free the context
	argon2_delete(actx);

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
