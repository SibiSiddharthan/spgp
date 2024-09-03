/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <drbg.h>
#include <round.h>
#include <minmax.h>
#include <hmac.h>
#include <sha.h>

// Refer to NIST Special Publication 800-90A : Recommendation for Random Number Generation Using Deterministic Random Bit Generators
// Section 10.1.2

uint32_t get_entropy(void *buffer, size_t size);

static inline size_t get_approved_hash_ctx_size(hmac_algorithm algorithm)
{
	switch (algorithm)
	{
	case HMAC_SHA1:
		return sizeof(sha1_ctx);
	case HMAC_SHA224:
	case HMAC_SHA256:
		return sizeof(sha256_ctx);
	case HMAC_SHA384:
	case HMAC_SHA512:
	case HMAC_SHA512_224:
	case HMAC_SHA512_256:
		return sizeof(sha512_ctx);
	default:
		return 0;
	}
}

static void hmac_drbg_update(hmac_drbg *hdrbg, byte_t *provided, size_t provided_size)
{
	hmac_ctx *hctx = hdrbg->hctx;
	byte_t *key = hdrbg->key;
	byte_t *seed = hdrbg->seed;

	size_t output_size = hdrbg->output_size;
	byte_t byte;

	byte = 0x00;

	// K = HMAC (K, V || 0x00 || provided_data)
	hmac_update(hctx, seed, output_size);
	hmac_update(hctx, &byte, 1);

	if (provided != NULL)
	{
		hmac_update(hctx, provided, provided_size);
	}

	hmac_final(hctx, key, output_size);
	hmac_reset(hctx, key, output_size);

	// V = HMAC (K, V)
	hmac_update(hctx, seed, output_size);
	hmac_final(hctx, seed, output_size);
	hmac_reset(hctx, key, output_size);

	if (provided != NULL)
	{
		byte = 0x01;

		// K = HMAC(K, V || 0x01 || provided_data).
		hmac_update(hctx, seed, output_size);
		hmac_update(hctx, &byte, 1);
		hmac_update(hctx, provided, provided_size);
		hmac_final(hctx, key, output_size);
		hmac_reset(hctx, key, output_size);

		// V = HMAC (K, V)
		hmac_update(hctx, seed, output_size);
		hmac_final(hctx, seed, output_size);
		hmac_reset(hctx, key, output_size);
	}
}

static int32_t hmac_drbg_init_state(hmac_drbg *hdrbg, size_t output_size, hmac_algorithm algorithm, void *personalization,
									size_t personalization_size)
{
	int32_t status = -1;
	uint32_t entropy_received = 0;
	size_t total_entropy_size = hdrbg->min_entropy_size + hdrbg->min_nonce_size;
	size_t seed_material_size = total_entropy_size + personalization_size;

	byte_t *seed_material = NULL;
	size_t seed_input_size = 0;

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
	}

	memset(hdrbg->key, 0x00, output_size);
	memset(hdrbg->seed, 0x01, output_size);

	hmac_init(hdrbg->hctx, hdrbg->drbg_size - sizeof(hmac_drbg), algorithm, hdrbg->key, output_size);
	hmac_drbg_update(hdrbg, seed_material, seed_material_size);

	hdrbg->reseed_counter = 1;

	status = 0;

end:
	free(seed_material);
	return status;
}

static hmac_drbg *hmac_drbg_init_checked(void *ptr, size_t ctx_size, uint32_t (*entropy)(void *buffer, size_t size),
										 hmac_algorithm algorithm, uint32_t reseed_interval, void *personalization,
										 size_t personalization_size)
{
	hmac_drbg *hdrbg = (hmac_drbg *)ptr;

	uint16_t output_size;
	uint16_t min_entropy_size;
	uint16_t min_nonce_size;
	uint16_t security_strength;

	switch (algorithm)
	{
	case HMAC_SHA1:
		output_size = SHA1_HASH_SIZE;
		min_entropy_size = 20;
		min_nonce_size = 10;
		security_strength = 160;
		break;

	case HMAC_SHA224:
	case HMAC_SHA512_224:
		output_size = SHA224_HASH_SIZE;
		min_entropy_size = 28;
		min_nonce_size = 14;
		security_strength = 224;
		break;

	case HMAC_SHA256:
	case HMAC_SHA512_256:
		output_size = SHA256_HASH_SIZE;
		min_entropy_size = 32;
		min_nonce_size = 16;
		security_strength = 256;
		break;

	case HMAC_SHA384:
		output_size = SHA384_HASH_SIZE;
		min_entropy_size = 48;
		min_nonce_size = 24;
		security_strength = 384;
		break;

	case HMAC_SHA512:
		output_size = SHA512_HASH_SIZE;
		min_entropy_size = 64;
		min_nonce_size = 32;
		security_strength = 512;
		break;
	default: // Prevent -Wswitch
		return NULL;
	}

	memset(hdrbg, 0, sizeof(hmac_drbg));

	hdrbg->hctx = (hmac_ctx *)((byte_t *)hdrbg + sizeof(hmac_drbg));
	hdrbg->drbg_size = sizeof(hmac_drbg) + sizeof(hmac_ctx) + ctx_size;
	hdrbg->reseed_interval = reseed_interval;
	hdrbg->output_size = output_size;
	hdrbg->min_entropy_size = min_entropy_size;
	hdrbg->min_nonce_size = min_nonce_size;
	hdrbg->security_strength = security_strength;
	hdrbg->entropy = entropy == NULL ? get_entropy : entropy;

	if (hmac_drbg_init_state(hdrbg, output_size, algorithm, personalization, personalization_size) != 0)
	{
		memset(hdrbg, 0, hdrbg->drbg_size);
		return NULL;
	}

	return hdrbg;
}

size_t hmac_drbg_size(hmac_algorithm algorithm)
{
	return sizeof(hmac_drbg) + sizeof(hmac_ctx) + get_approved_hash_ctx_size(algorithm);
}

hmac_drbg *hmac_drbg_init(void *ptr, size_t size, uint32_t (*entropy)(void *buffer, size_t size), hmac_algorithm algorithm,
						  uint32_t reseed_interval, void *personalization, size_t personalization_size)
{

	size_t ctx_size = get_approved_hash_ctx_size(algorithm);
	size_t required_size = sizeof(hmac_drbg) + sizeof(hmac_ctx) + ctx_size;

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

	return hmac_drbg_init_checked(ptr, ctx_size, entropy, algorithm, reseed_interval, personalization, personalization_size);
}

hmac_drbg *hmac_drbg_new(uint32_t (*entropy)(void *buffer, size_t size), hmac_algorithm algorithm, uint32_t reseed_interval,
						 void *personalization, size_t personalization_size)
{
	hmac_drbg *hdrbg = NULL;
	hmac_drbg *result = NULL;

	size_t ctx_size = get_approved_hash_ctx_size(algorithm);
	size_t required_size = sizeof(hmac_drbg) + sizeof(hmac_ctx) + ctx_size;

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (personalization_size > MAX_PERSONALIZATION_SIZE)
	{
		return NULL;
	}

	hdrbg = (hmac_drbg *)malloc(required_size);

	if (hdrbg == NULL)
	{
		return NULL;
	}

	result = hmac_drbg_init_checked(hdrbg, ctx_size, entropy, algorithm, reseed_interval, personalization, personalization_size);

	if (result == NULL)
	{
		free(hdrbg);
		return NULL;
	}

	return result;
}

void hmac_drbg_delete(hmac_drbg *hdrbg)
{
	memset(hdrbg, 0, hdrbg->drbg_size);
	free(hdrbg);
}

int32_t hmac_drbg_reseed(hmac_drbg *hdrbg, void *additional_input, size_t input_size)
{
	uint32_t entropy_received = 0;
	size_t seed_material_size = hdrbg->min_entropy_size + input_size;

	byte_t *seed_material = NULL;

	seed_material = (byte_t *)malloc(seed_material_size);

	if (seed_material == NULL)
	{
		return -1;
	}

	entropy_received = hdrbg->entropy(seed_material, hdrbg->min_entropy_size);

	if (entropy_received < hdrbg->min_entropy_size)
	{
		free(seed_material);
		return -1;
	}

	if (additional_input != NULL && input_size > 0)
	{
		memcpy(seed_material + hdrbg->min_entropy_size, additional_input, input_size);
	}

	hmac_drbg_update(hdrbg, seed_material, seed_material_size);
	hdrbg->reseed_counter = 1;

	free(seed_material);
	return 0;
}

int32_t hmac_drbg_generate(hmac_drbg *hdrbg, uint32_t prediction_resistance_request, void *additional_input, size_t input_size,
						   void *output, size_t output_size)
{
	int32_t status = 0;

	hmac_ctx *hctx = hdrbg->hctx;
	byte_t *pout = output;

	size_t count = 0;
	size_t hmac_size = hdrbg->output_size;

	// Check buffer
	if (output == NULL)
	{
		return -1;
	}

	// Check requested size
	if (output_size > MAX_DRBG_OUTPUT_SIZE)
	{
		return -1;
	}

	// Reseed
	if (hdrbg->reseed_counter == hdrbg->reseed_interval || prediction_resistance_request > 0)
	{
		status = hmac_drbg_reseed(hdrbg, additional_input, input_size);

		additional_input = NULL;
		input_size = 0;

		if (status == -1)
		{
			return -1;
		}
	}

	if (additional_input != NULL && input_size > 0)
	{
		hmac_drbg_update(hdrbg, additional_input, input_size);
	}

	while (count < output_size)
	{
		hmac_update(hctx, hdrbg->seed, hmac_size);
		hmac_final(hctx, hdrbg->seed, hmac_size);
		hmac_reset(hctx, hdrbg->key, hmac_size);

		memcpy(pout + count, hdrbg->seed, MIN(output_size - count, hmac_size));
		count += MIN(output_size - count, hmac_size);
	}

	hmac_drbg_update(hdrbg, additional_input, input_size);
	hdrbg->reseed_counter++;

	return 0;
}
