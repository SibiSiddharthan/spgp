/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <drbg.h>
#include <cipher.h>
#include <aes.h>

#include <stdlib.h>
#include <string.h>

// Refer to NIST Special Publication 800-90A : Recommendation for Random Number Generation Using Deterministic Random Bit Generators
// Section 10.2.1

#define MAX_CTR_SEED_SIZE 64

uint32_t get_entropy(void *state, void *buffer, uint32_t size);

static inline size_t get_approved_cipher_ctx_size(cipher_algorithm algorithm)
{
	switch (algorithm)
	{
	// Only support AES
	case CIPHER_AES128:
	case CIPHER_AES192:
	case CIPHER_AES256:
		return sizeof(aes_key);
	default:
		return 0;
	}
}

static void bcc(ctr_drbg *cdrbg, byte_t *plaintext, size_t plaintext_size, byte_t *ciphertext, size_t ciphertext_size)
{
	byte_t chain[AES_BLOCK_SIZE] = {0};

	while (plaintext_size != 0)
	{
		for (uint16_t i = 0; i < cdrbg->block_size; ++i)
		{
			chain[i] ^= plaintext[i];
		}

		cdrbg->_encrypt(cdrbg->_dfctx, chain, chain);

		plaintext += cdrbg->block_size;
		plaintext_size -= cdrbg->block_size;
	}

	memcpy(ciphertext, chain, ciphertext_size);
}

static int32_t ctr_drbg_df(ctr_drbg *cdrbg, byte_t *input, size_t input_size, byte_t *output, size_t output_size)
{

	byte_t base_key[AES256_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
										0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

	uint32_t l = BSWAP_32((uint32_t)input_size);
	uint32_t n = BSWAP_32((uint32_t)output_size);

	byte_t *s = NULL;
	size_t size = ROUND_UP(input_size + (sizeof(uint32_t) * 2) + 1, AES_BLOCK_SIZE) + AES_BLOCK_SIZE;

	size_t pos = 0;
	byte_t count = 0;

	byte_t temp[MAX_CTR_SEED_SIZE] = {0};
	size_t temp_size = 0;

	byte_t new_key[AES256_KEY_SIZE] = {0};
	byte_t new_block[AES_BLOCK_SIZE] = {0};

	s = (byte_t *)malloc(size);

	if (s == NULL)
	{
		return -1;
	}

	memset(s, 0, size);
	pos += AES_BLOCK_SIZE;

	memcpy(s + pos, &l, sizeof(uint32_t));
	pos += sizeof(uint32_t);

	memcpy(s + pos, &n, sizeof(uint32_t));
	pos += sizeof(uint32_t);

	memcpy(s + pos, input, input_size);
	pos += input_size;

	s[pos++] = 0x80;

	cdrbg->_init(cdrbg->_dfctx, base_key);

	while (temp_size < cdrbg->seed_size)
	{
		// Last byte of integer.
		s[3] = count;

		bcc(cdrbg, s, size, temp + temp_size, cdrbg->block_size);
		temp_size += cdrbg->block_size;

		++count;
	}

	memcpy(new_key, temp, cdrbg->key_size);
	memcpy(new_block, temp + cdrbg->key_size, cdrbg->block_size);

	cdrbg->_init(cdrbg->_dfctx, new_key);

	memset(temp, 0, MAX_CTR_SEED_SIZE);
	temp_size = 0;

	while (temp_size < output_size)
	{
		cdrbg->_encrypt(cdrbg->_dfctx, new_block, new_block);

		memcpy(temp + temp_size, new_block, cdrbg->block_size);
		temp_size += cdrbg->block_size;
	}

	memcpy(output, temp, output_size);

	free(s);

	return 0;
}

static void ctr_drbg_update(ctr_drbg *cdrbg, byte_t *provided)
{
	size_t block_size = cdrbg->block_size;
	size_t seed_size = cdrbg->seed_size;

	byte_t temp[MAX_CTR_SEED_SIZE] = {0};
	size_t temp_size = 0;

	// Rightmost 64 bits
	uint64_t *inc = (uint64_t *)(cdrbg->block + (block_size - 8));

	while (temp_size < seed_size)
	{
		*inc = BSWAP_64(BSWAP_64(*inc) + 1);

		cdrbg->_encrypt(cdrbg->_ctx, cdrbg->block, temp + temp_size);
		temp_size += block_size;
	}

	for (uint16_t i = 0; i < seed_size; ++i)
	{
		temp[i] ^= provided[i];
	}

	memcpy(cdrbg->key, temp, cdrbg->key_size);
	memcpy(cdrbg->block, temp + (seed_size - block_size), block_size);

	cdrbg->_init(cdrbg->_ctx, cdrbg->key);
}

static int32_t ctr_drbg_init_state(ctr_drbg *cdrbg, void *personalization, size_t personalization_size)
{
	int32_t status = -1;
	uint32_t entropy_received = 0;
	size_t total_entropy_size = cdrbg->min_entropy_size + cdrbg->min_nonce_size;
	size_t seed_material_size = cdrbg->seed_size + total_entropy_size + personalization_size;

	byte_t *seed_material = NULL;
	byte_t *seed = NULL;
	size_t seed_input_size = 0;

	seed_material = (byte_t *)malloc(seed_material_size);

	if (seed_material == NULL)
	{
		return status;
	}

	// Entropy and Nonce
	entropy_received = cdrbg->entropy(NULL, seed_material, total_entropy_size);
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

	seed = seed_material + seed_input_size;

	status = ctr_drbg_df(cdrbg, seed_material, seed_input_size, seed, cdrbg->seed_size);

	if (status != 0)
	{
		goto end;
	}

	memset(cdrbg->key, 0, cdrbg->key_size);
	memset(cdrbg->block, 0, cdrbg->block_size);

	cdrbg->_init(cdrbg->_ctx, cdrbg->key);
	ctr_drbg_update(cdrbg, seed);

	cdrbg->reseed_counter = 1;

	status = 0;

end:
	free(seed_material);
	return status;
}

static ctr_drbg *ctr_drbg_init_checked(void *ptr, size_t ctx_size, uint32_t (*entropy)(void *state, void *buffer, uint32_t size),
									   cipher_algorithm algorithm, uint32_t reseed_interval, void *personalization,
									   size_t personalization_size)
{
	ctr_drbg *cdrbg = (ctr_drbg *)ptr;

	uint16_t security_strength;
	uint16_t key_size;
	uint16_t seed_size;
	uint16_t block_size;
	uint16_t min_entropy_size;
	uint16_t min_nonce_size;

	void (*_init)(void *, void *) = NULL;
	void (*_encrypt)(void *, void *, void *) = NULL;

	switch (algorithm)
	{
	// Only support AES
	case CIPHER_AES128:
		security_strength = 128;
		key_size = 16;
		min_entropy_size = 16;
		min_nonce_size = 8;

		_init = (void (*)(void *, void *))aes128_key_init;
		_encrypt = (void (*)(void *, void *, void *))aes128_encrypt_block;
		break;
	case CIPHER_AES192:
		security_strength = 192;
		key_size = 24;
		min_entropy_size = 24;
		min_nonce_size = 12;

		_init = (void (*)(void *, void *))aes192_key_init;
		_encrypt = (void (*)(void *, void *, void *))aes192_encrypt_block;
		break;
	case CIPHER_AES256:
		security_strength = 256;
		key_size = 32;
		min_entropy_size = 32;
		min_nonce_size = 16;

		_init = (void (*)(void *, void *))aes256_key_init;
		_encrypt = (void (*)(void *, void *, void *))aes256_encrypt_block;
		break;
	default: // Prevent -Wswitch
		return NULL;
	}

	block_size = 16;
	seed_size = key_size + block_size;

	memset(cdrbg, 0, sizeof(ctr_drbg));

	cdrbg->drbg_size = sizeof(ctr_drbg) + (ctx_size * 2);
	cdrbg->reseed_interval = reseed_interval;
	cdrbg->key_size = key_size;
	cdrbg->block_size = block_size;
	cdrbg->seed_size = seed_size;
	cdrbg->min_entropy_size = min_entropy_size;
	cdrbg->min_nonce_size = min_nonce_size;
	cdrbg->security_strength = security_strength;
	cdrbg->entropy = entropy == NULL ? get_entropy : entropy;

	cdrbg->_ctx = PTR_OFFSET(cdrbg, sizeof(ctr_drbg));
	cdrbg->_dfctx = PTR_OFFSET(cdrbg->_ctx, ctx_size);
	cdrbg->_size = ctx_size;
	cdrbg->_algorithm = algorithm;
	cdrbg->_init = _init;
	cdrbg->_encrypt = _encrypt;

	if (ctr_drbg_init_state(cdrbg, personalization, personalization_size) != 0)
	{
		memset(cdrbg, 0, cdrbg->drbg_size);
		return NULL;
	}

	return cdrbg;
}

size_t ctr_drbg_size(cipher_algorithm algorithm)
{
	return sizeof(ctr_drbg) + (get_approved_cipher_ctx_size(algorithm) * 2);
}

ctr_drbg *ctr_drbg_init(void *ptr, size_t size, uint32_t (*entropy)(void *state, void *buffer, uint32_t size), cipher_algorithm algorithm,
						uint32_t reseed_interval, void *personalization, size_t personalization_size)
{

	size_t ctx_size = get_approved_cipher_ctx_size(algorithm);
	size_t required_size = sizeof(ctr_drbg) + (ctx_size * 2);

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

	return ctr_drbg_init_checked(ptr, ctx_size, entropy, algorithm, reseed_interval, personalization, personalization_size);
}

ctr_drbg *ctr_drbg_new(uint32_t (*entropy)(void *state, void *buffer, uint32_t size), cipher_algorithm algorithm, uint32_t reseed_interval,
					   void *personalization, size_t personalization_size)
{
	ctr_drbg *cdrbg = NULL;
	ctr_drbg *result = NULL;

	size_t ctx_size = get_approved_cipher_ctx_size(algorithm);
	size_t required_size = sizeof(ctr_drbg) + (ctx_size * 2);

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (personalization_size > MAX_PERSONALIZATION_SIZE)
	{
		return NULL;
	}

	cdrbg = (ctr_drbg *)malloc(required_size);

	if (cdrbg == NULL)
	{
		return NULL;
	}

	result = ctr_drbg_init_checked(cdrbg, ctx_size, entropy, algorithm, reseed_interval, personalization, personalization_size);

	if (result == NULL)
	{
		free(cdrbg);
		return NULL;
	}

	return result;
}

void ctr_drbg_delete(ctr_drbg *cdrbg)
{
	memset(cdrbg, 0, cdrbg->drbg_size);
	free(cdrbg);
}

uint32_t ctr_drbg_reseed(ctr_drbg *cdrbg, void *additional_input, size_t input_size)
{
	int32_t status = -1;
	uint32_t entropy_received = 0;
	size_t seed_material_size = cdrbg->min_entropy_size + cdrbg->seed_size + input_size;

	byte_t *seed_material = NULL;
	byte_t *seed = NULL;
	size_t seed_input_size = 0;

	seed_material = (byte_t *)malloc(seed_material_size);

	if (seed_material == NULL)
	{
		return 0;
	}

	entropy_received = cdrbg->entropy(NULL, seed_material, cdrbg->min_entropy_size);
	seed_input_size += cdrbg->min_entropy_size;

	if (entropy_received < cdrbg->min_entropy_size)
	{
		free(seed_material);
		return 0;
	}

	if (additional_input != NULL && input_size > 0)
	{
		memcpy(seed_material + seed_input_size, additional_input, input_size);
		seed_input_size += input_size;
	}

	seed = seed_material + seed_input_size;

	status = ctr_drbg_df(cdrbg, seed_material, seed_input_size, seed, cdrbg->seed_size);

	if (status != 0)
	{
		return 0;
	}

	ctr_drbg_update(cdrbg, seed);

	cdrbg->reseed_counter = 1;

	free(seed_material);
	return 1;
}

uint32_t ctr_drbg_generate(ctr_drbg *cdrbg, uint32_t prediction_resistance_request, void *additional_input, size_t input_size, void *output,
						   size_t output_size)
{
	int32_t status;

	byte_t seed[MAX_CTR_SEED_SIZE] = {0};
	byte_t temp[AES_BLOCK_SIZE] = {0};

	size_t count = 0;
	size_t seed_size = cdrbg->seed_size;
	size_t block_size = cdrbg->block_size;

	// Rightmost 64 bits
	uint64_t *inc = (uint64_t *)(cdrbg->block + (block_size - 8));

	// Check requested size
	if (output_size > MAX_DRBG_OUTPUT_SIZE)
	{
		return -1u;
	}

	// Reseed
	if (cdrbg->reseed_counter == cdrbg->reseed_interval || prediction_resistance_request > 0)
	{
		status = ctr_drbg_reseed(cdrbg, additional_input, input_size);

		additional_input = NULL;
		input_size = 0;

		if (status == 0)
		{
			return 0;
		}
	}

	if (additional_input != NULL && input_size > 0)
	{
		status = ctr_drbg_df(cdrbg, additional_input, input_size, seed, seed_size);

		if (status != 0)
		{
			return 0;
		}

		ctr_drbg_update(cdrbg, seed);
	}

	while ((count + block_size) <= output_size)
	{
		*inc = BSWAP_64(BSWAP_64(*inc) + 1);

		cdrbg->_encrypt(cdrbg->_ctx, cdrbg->block, (byte_t *)output + count);
		count += block_size;
	}

	if ((output_size - count) != 0)
	{
		*inc = BSWAP_64(BSWAP_64(*inc) + 1);

		cdrbg->_encrypt(cdrbg->_ctx, cdrbg->block, temp);
		memcpy((byte_t *)output + count, temp, output_size - count);
	}

	ctr_drbg_update(cdrbg, seed);
	cdrbg->reseed_counter++;

	return output_size;
}
