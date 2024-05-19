/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <drbg.h>

#define MAX_ENTROPY_SIZE 128
#define MAX_NONCE_SIZE   128

int32_t get_entropy(byte_t *buffer, size_t size);
int32_t get_nonce(byte_t *buffer, size_t size);

static void hash_df(byte_t *seed_material, size_t seed_material_size, byte_t *seed, size_t seed_size);

static int32_t hash_drbg_init_state(hash_drbg *hdrbg, byte_t *personalization, size_t personalization_size)
{
	int32_t status = -1;
	size_t security = hdrbg->security_strength / 8;
	size_t seed_material_size = (2 * security) + personalization_size;

	byte_t seed_material[MAX_ENTROPY_SIZE + MAX_NONCE_SIZE + MAX_PERSONALIZATION_SIZE] = {0};

	status = get_entropy(seed_material, security);

	if (status != 0)
	{
		return -1;
	}

	status = get_nonce(seed_material + security, security);

	if (status != 0)
	{
		return -1;
	}

	if (personalization != NULL)
	{
		memcpy(seed_material + (2 * security), personalization, personalization_size);
	}

	hash_df(seed_material, seed_material_size, hdrbg->seed, hdrbg->seed_size);

	// Reuse the same buffer
	seed_material[0] = 0x00;
	memcpy(seed_material + 1, hdrbg->seed, hdrbg->seed_size);

	hash_df(seed_material, hdrbg->seed_size + 1, hdrbg->constant, hdrbg->seed_size);

	hdrbg->reseed_counter = 1;

	return 0;
}

hash_drbg *hash_drbg_init(void *ptr, size_t size, hash_algorithm algorithm, uint32_t reseed_interval, byte_t *personalization, size_t personalization_size)
{

}

hash_drbg *hash_drbg_new(hash_algorithm algorithm, uint32_t reseed_interval, byte_t *personalization, size_t personalization_size)
{
	hash_drbg *hdrbg = NULL;
	hash_ctx *hctx = NULL;

	uint16_t seed_size;
	uint16_t security_strength;

	if (personalization_size > MAX_PERSONALIZATION_SIZE)
	{
		return NULL;
	}

	switch (algorithm)
	{
	case SHA1:
		seed_size = 55;
		security_strength = 160;
		break;

	case SHA224:
	case SHA512_224:
		seed_size = 55;
		security_strength = 224;
		break;

	case SHA256:
	case SHA512_256:
		seed_size = 55;
		security_strength = 256;
		break;

	case SHA384:
		seed_size = 111;
		security_strength = 384;
		break;

	case SHA512:
		seed_size = 111;
		security_strength = 512;
		break;

	default:
		return NULL;
	}

	hdrbg = (hash_drbg *)malloc(sizeof(hash_drbg));

	if (hdrbg == NULL)
	{
		return NULL;
	}

	hctx = hash_new(algorithm);

	if (hctx == NULL)
	{
		free(hdrbg);
		return NULL;
	}

	memset(hdrbg, 0, sizeof(hash_drbg));

	hdrbg->hctx = hctx;
	hdrbg->reseed_interval = reseed_interval;
	hdrbg->seed_size = seed_size;
	hdrbg->security_strength = security_strength;

	if (hash_drbg_init_state(hdrbg, personalization, personalization_size) != 0)
	{
		hash_delete(hdrbg->hctx);
		memset(hdrbg, 0, sizeof(hash_drbg));
		free(hdrbg);

		return NULL;
	}

	return hdrbg;
}

void hash_drbg_delete(hash_drbg *hdrbg)
{
	hash_delete(hdrbg->hctx);
	memset(hdrbg, 0, sizeof(hash_drbg));
	free(hdrbg);
}

int32_t hash_drbg_reseed(hash_drbg *hdrbg, byte_t *additional_input, size_t input_size)
{
	int32_t status = -1;
	size_t pos = 0;
	size_t security = hdrbg->security_strength / 8;
	size_t seed_material_size = 1 + hdrbg->seed_size + security + input_size;

	byte_t seed_material[1 + MAX_ENTROPY_SIZE + MAX_SEED_SIZE + MAX_ADDITIONAL_INPUT_SIZE] = {0};

	seed_material[pos++] = 0x01;

	memcpy(seed_material + pos, hdrbg->seed, hdrbg->seed_size);
	pos += hdrbg->seed_size;

	status = get_entropy(seed_material + pos, security);
	pos += security;

	if (status != 0)
	{
		return -1;
	}

	if (additional_input != NULL)
	{
		memcpy(seed_material + pos, additional_input, input_size);
	}

	hash_df(seed_material, seed_material_size, hdrbg->seed, hdrbg->seed_size);

	// Reuse the same buffer
	seed_material[0] = 0x00;
	memcpy(seed_material + 1, hdrbg->seed, hdrbg->seed_size);

	hash_df(seed_material, hdrbg->seed_size + 1, hdrbg->constant, hdrbg->seed_size);

	hdrbg->reseed_counter = 1;

	return 0;
}

void hash_drbg_generate(hash_drbg *drbg, void *buffer, size_t size);
