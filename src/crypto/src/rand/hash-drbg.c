/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <drbg.h>
#include <hash.h>
#include <sha.h>

#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>
#include <round.h>

// Refer to NIST Special Publication 800-90A : Recommendation for Random Number Generation Using Deterministic Random Bit Generators
// Section 10.1.1

#define MAX_ENTROPY_SIZE 128
#define MAX_NONCE_SIZE   128

uint32_t get_entropy(void *buffer, size_t size);

static inline size_t get_approved_hash_ctx_size(hash_algorithm algorithm)
{
	switch (algorithm)
	{
	case HASH_SHA1:
		return sizeof(sha1_ctx);
	case HASH_SHA224:
	case HASH_SHA256:
		return sizeof(sha256_ctx);
	case HASH_SHA384:
	case HASH_SHA512:
	case HASH_SHA512_224:
	case HASH_SHA512_256:
		return sizeof(sha512_ctx);
	default:
		return 0;
	}
}

// a = (a + b) % 2^(s*8), sa = s
static void add_bytes_be(void *a, size_t sa, void *b, size_t sb, size_t s)
{
	size_t c = 0;
	byte_t *pa = (byte_t *)a + (sa - 1);
	byte_t *pb = (byte_t *)b + (sb - 1);
	byte_t carry = 0, ta, tb;

	for (c = 0; c < s; ++c)
	{
		ta = *pa;
		tb = (pb >= (byte_t *)b) ? *pb : 0;

		*pa += carry;
		carry = (*pa < ta);
		*pa += tb;
		carry |= (*pa < tb);

		pa--;
		pb--;
	}
}

// a = (a + 1) % 2^(s*8), len(a) = s
static void increment_be(void *a, size_t s)
{
	size_t c = 0;
	byte_t *p = (byte_t *)a + (s - 1);

	for (c = 0; c < s; ++c)
	{
		++(*p);

		// No carry
		if (*p != 0)
		{
			return;
		}

		p--;
	}
}

static void hash_df(hash_ctx *hctx, byte_t *seed_material, size_t seed_material_size, byte_t *output, size_t output_size)
{
	size_t hash_size = hctx->hash_size;
	uint32_t output_bits = BSWAP_32((uint32_t)(output_size << 3));
	size_t output_count = 0;
	byte_t counter = 1;

	while (output_count <= output_size)
	{
		hash_update(hctx, &counter, 1);
		hash_update(hctx, &output_bits, 4);
		hash_update(hctx, seed_material, seed_material_size);
		hash_final(hctx, output + output_count, MIN(output_size - output_count, hash_size));
		hash_reset(hctx);

		output_count += hash_size;
		counter++;
	}
}

static void hash_gen(hash_drbg *hdrbg, void *output, size_t output_size)
{
	byte_t *op = (byte_t *)output;
	size_t count = 0;

	hash_ctx *hctx = hdrbg->hctx;
	size_t hash_size = hctx->hash_size;

	byte_t data[MAX_SEED_SIZE] = {0};

	memcpy(data, hdrbg->seed, hdrbg->seed_size);

	while (count <= output_size)
	{
		hash_update(hctx, data, hdrbg->seed_size);
		hash_final(hctx, op + count, MIN(output_size - count, hash_size));
		hash_reset(hctx);

		increment_be(data, hdrbg->seed_size);

		count += hash_size;
	}
}

static int32_t hash_drbg_init_state(hash_drbg *hdrbg, void *personalization, size_t personalization_size)
{
	int32_t status = -1;
	uint32_t entropy_received = 0;

	size_t total_entropy_size = hdrbg->min_entropy_size + hdrbg->min_nonce_size;
	size_t seed_material_size = 128 + personalization_size;

	byte_t *seed_material = NULL;
	size_t seed_input_size = 0;

	// seed_material = entropy_input || nonce || personalization_string
	seed_material = (byte_t *)malloc(seed_material_size);

	if (seed_material == NULL)
	{
		return status;
	}

	// Entropy and Nonce
	entropy_received = hdrbg->entropy(seed_material, total_entropy_size);
	seed_input_size += total_entropy_size;

	if (entropy_received < total_entropy_size)
	{
		goto end;
	}

	if (personalization != NULL)
	{
		memcpy(seed_material + seed_input_size, personalization, personalization_size);
		seed_input_size += personalization_size;
	}

	hash_df(hdrbg->hctx, seed_material, seed_input_size, hdrbg->seed, hdrbg->seed_size);

	// Reuse the same buffer
	seed_material[0] = 0x00;
	memcpy(seed_material + 1, hdrbg->seed, hdrbg->seed_size);

	hash_df(hdrbg->hctx, seed_material, hdrbg->seed_size + 1, hdrbg->constant, hdrbg->seed_size);

	hdrbg->reseed_counter = 1;

	status = 0;

end:
	free(seed_material);
	return status;
}

static hash_drbg *hash_drbg_init_checked(void *ptr, size_t ctx_size, uint32_t (*entropy)(void *buffer, size_t size),
										 hash_algorithm algorithm, uint32_t reseed_interval, void *personalization,
										 size_t personalization_size)
{
	hash_drbg *hdrbg = (hash_drbg *)ptr;

	uint16_t seed_size;
	uint16_t min_entropy_size;
	uint16_t min_nonce_size;
	uint16_t security_strength;

	switch (algorithm)
	{
	case HASH_SHA1:
		seed_size = 55;
		min_entropy_size = 20;
		min_nonce_size = 10;
		security_strength = 160;
		break;

	case HASH_SHA224:
	case HASH_SHA512_224:
		seed_size = 55;
		min_entropy_size = 28;
		min_nonce_size = 14;
		security_strength = 224;
		break;

	case HASH_SHA256:
	case HASH_SHA512_256:
		seed_size = 55;
		min_entropy_size = 32;
		min_nonce_size = 16;
		security_strength = 256;
		break;

	case HASH_SHA384:
		seed_size = 111;
		min_entropy_size = 48;
		min_nonce_size = 24;
		security_strength = 384;
		break;

	case HASH_SHA512:
		seed_size = 111;
		min_entropy_size = 64;
		min_nonce_size = 32;
		security_strength = 512;
		break;
	default: // Prevent -Wswitch
		return NULL;
	}

	memset(hdrbg, 0, sizeof(hash_drbg));

	hdrbg->hctx = PTR_OFFSET(hdrbg, sizeof(hash_drbg));
	hdrbg->drbg_size = sizeof(hash_drbg) + sizeof(hash_ctx) + ctx_size;
	hdrbg->reseed_interval = reseed_interval;
	hdrbg->seed_size = seed_size;
	hdrbg->min_entropy_size = min_entropy_size;
	hdrbg->min_nonce_size = min_nonce_size;
	hdrbg->security_strength = security_strength;
	hdrbg->entropy = entropy == NULL ? get_entropy : entropy;

	hash_init(hdrbg->hctx, sizeof(hash_ctx) + ctx_size, algorithm);

	if (hash_drbg_init_state(hdrbg, personalization, personalization_size) != 0)
	{
		memset(hdrbg, 0, hdrbg->drbg_size);
		return NULL;
	}

	return hdrbg;
}

size_t hash_drbg_size(hash_algorithm algorithm)
{
	return sizeof(hash_drbg) + sizeof(hash_ctx) + get_approved_hash_ctx_size(algorithm);
}

hash_drbg *hash_drbg_init(void *ptr, size_t size, uint32_t (*entropy)(void *buffer, size_t size), hash_algorithm algorithm,
						  uint32_t reseed_interval, void *personalization, size_t personalization_size)
{

	size_t ctx_size = get_approved_hash_ctx_size(algorithm);
	size_t required_size = sizeof(hash_drbg) + sizeof(hash_ctx) + ctx_size;

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (size < required_size)
	{
		return NULL;
	}

	if (personalization_size > MAX_PERSONALIZATION_SIZE)
	{
		return NULL;
	}

	return hash_drbg_init_checked(ptr, ctx_size, entropy, algorithm, reseed_interval, personalization, personalization_size);
}

hash_drbg *hash_drbg_new(uint32_t (*entropy)(void *buffer, size_t size), hash_algorithm algorithm, uint32_t reseed_interval,
						 void *personalization, size_t personalization_size)
{
	hash_drbg *hdrbg = NULL;
	hash_drbg *result = NULL;

	size_t ctx_size = get_approved_hash_ctx_size(algorithm);
	size_t required_size = sizeof(hash_drbg) + sizeof(hash_ctx) + ctx_size;

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (personalization_size > MAX_PERSONALIZATION_SIZE)
	{
		return NULL;
	}

	hdrbg = (hash_drbg *)malloc(required_size);

	if (hdrbg == NULL)
	{
		return NULL;
	}

	result = hash_drbg_init_checked(hdrbg, ctx_size, entropy, algorithm, reseed_interval, personalization, personalization_size);

	if (result == NULL)
	{
		free(hdrbg);
		return NULL;
	}

	return result;
}

void hash_drbg_delete(hash_drbg *hdrbg)
{
	memset(hdrbg, 0, hdrbg->drbg_size);
	free(hdrbg);
}

int32_t hash_drbg_reseed(hash_drbg *hdrbg, void *additional_input, size_t input_size)
{
	uint32_t entropy_received = 0;
	size_t seed_material_size = 1 + hdrbg->seed_size + hdrbg->min_entropy_size + input_size;

	byte_t *seed_material = NULL;
	size_t seed_input_size = 0;

	seed_material = (byte_t *)malloc(seed_material_size);

	if (seed_material == NULL)
	{
		return -1;
	}

	// seed_material = 0x01 || V || entropy_input || additional_input
	seed_material[seed_input_size++] = 0x01;

	memcpy(seed_material + seed_input_size, hdrbg->seed, hdrbg->seed_size);
	seed_input_size += hdrbg->seed_size;

	entropy_received = hdrbg->entropy(seed_material + seed_input_size, hdrbg->min_entropy_size);
	seed_input_size += hdrbg->min_entropy_size;

	if (entropy_received < hdrbg->min_entropy_size)
	{
		free(seed_material);
		return -1;
	}

	if (additional_input != NULL)
	{
		memcpy(seed_material + seed_input_size, additional_input, input_size);
	}

	hash_df(hdrbg->hctx, seed_material, seed_material_size, hdrbg->seed, hdrbg->seed_size);

	// Reuse the same buffer
	seed_material[0] = 0x00;
	memcpy(seed_material + 1, hdrbg->seed, hdrbg->seed_size);

	hash_df(hdrbg->hctx, seed_material, hdrbg->seed_size + 1, hdrbg->constant, hdrbg->seed_size);

	hdrbg->reseed_counter = 1;

	free(seed_material);
	return 0;
}

int32_t hash_drbg_generate(hash_drbg *hdrbg, uint32_t prediction_resistance_request, void *additional_input, size_t input_size,
						   void *output, size_t output_size)
{
	int32_t status = 0;
	hash_ctx *hctx = hdrbg->hctx;
	uint64_t reseed_counter = 0;

	byte_t hash[MAX_HASH_SIZE] = {0};

	// Check requested size
	if (output_size > MAX_DRBG_OUTPUT_SIZE)
	{
		return -1;
	}

	// Reseed
	if (hdrbg->reseed_counter == hdrbg->reseed_interval || prediction_resistance_request > 0)
	{
		status = hash_drbg_reseed(hdrbg, additional_input, input_size);

		additional_input = NULL;
		input_size = 0;

		if (status == -1)
		{
			return -1;
		}
	}

	reseed_counter = BSWAP_64(hdrbg->reseed_counter);

	if (additional_input != NULL && input_size > 0)
	{
		// hash(0x02 || V || additional_input)
		hash_update(hctx, "\x02", 1);
		hash_update(hctx, hdrbg->seed, hdrbg->seed_size);
		hash_update(hctx, additional_input, input_size);

		hash_final(hctx, hash, MAX_HASH_SIZE);
		hash_reset(hctx);

		add_bytes_be(hdrbg->seed, hdrbg->seed_size, hash, hctx->hash_size, hdrbg->seed_size);
	}

	hash_gen(hdrbg, output, output_size);

	// hash(0x03 || V)
	hash_update(hctx, "\x03", 1);
	hash_update(hctx, hdrbg->seed, hdrbg->seed_size);

	hash_final(hctx, hash, MAX_HASH_SIZE);
	hash_reset(hctx);

	// V = (V + H + C + reseed_counter)
	add_bytes_be(hdrbg->seed, hdrbg->seed_size, hash, hctx->hash_size, hdrbg->seed_size);
	add_bytes_be(hdrbg->seed, hdrbg->seed_size, hdrbg->constant, hdrbg->seed_size, hdrbg->seed_size);
	add_bytes_be(hdrbg->seed, hdrbg->seed_size, &reseed_counter, sizeof(reseed_counter), hdrbg->seed_size);

	hdrbg->reseed_counter++;

	return 0;
}
