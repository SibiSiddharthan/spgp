/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <drbg.h>
#include <hash.h>
#include <hmac.h>
#include <cipher.h>
#include <sha.h>
#include <aes.h>

#include <byteswap.h>
#include <ptr.h>
#include <round.h>

drbg_ctx *default_drbg = NULL;

size_t drbg_ctx_size(drbg_type type, uint32_t algorithm)
{
	size_t ctx_size = sizeof(drbg_ctx);

	switch (type)
	{
	case HASH_DRBG:
		ctx_size += hash_drbg_size(algorithm);
		break;
	case HMAC_DRBG:
		ctx_size += hmac_drbg_size(algorithm);
		break;
	case CTR_DRBG:
		ctx_size += ctr_drbg_size(algorithm);
		break;
	default:
		return 0;
	}

	return ctx_size;
}

static drbg_ctx *drbg_init_checked(void *ptr, size_t ctx_size, uint32_t (*entropy)(void *buffer, size_t size), drbg_type type,
								   uint32_t algorithm, uint32_t reseed_interval, void *personalization, size_t personalization_size)
{
	drbg_ctx *drbg = (drbg_ctx *)ptr;

	void *_drbg = NULL;
	int32_t (*_reseed)(void *, void *, size_t) = NULL;
	int32_t (*_generate)(void *, uint32_t, void *, size_t, void *, size_t) = NULL;

	drbg->type = type;
	drbg->drbg_size = ctx_size + sizeof(drbg_ctx);
	drbg->_drbg = PTR_OFFSET(drbg, sizeof(drbg_ctx));

	switch (type)
	{
	case HASH_DRBG:
		_drbg = hash_drbg_init(drbg->_drbg, ctx_size, entropy, algorithm, reseed_interval, personalization, personalization_size);
		_reseed = (int32_t(*)(void *, void *, size_t))hash_drbg_reseed;
		_generate = (int32_t(*)(void *, uint32_t, void *, size_t, void *, size_t))hash_drbg_generate;
		break;
	case HMAC_DRBG:
		_drbg = hmac_drbg_init(drbg->_drbg, ctx_size, entropy, algorithm, reseed_interval, personalization, personalization_size);
		_generate = (int32_t(*)(void *, uint32_t, void *, size_t, void *, size_t))hmac_drbg_generate;
		break;
	case CTR_DRBG:
		_drbg = ctr_drbg_init(drbg->_drbg, ctx_size, entropy, algorithm, reseed_interval, personalization, personalization_size);
		_generate = (int32_t(*)(void *, uint32_t, void *, size_t, void *, size_t))ctr_drbg_generate;
		break;
	}

	if (_drbg == NULL)
	{
		return NULL;
	}

	drbg->_drbg = _drbg;
	drbg->_reseed = _reseed;
	drbg->_generate = _generate;

	return drbg;
}

drbg_ctx *drgb_init(void *ptr, size_t size, uint32_t (*entropy)(void *buffer, size_t size), drbg_type type, uint32_t algorithm,
					uint32_t reseed_interval, void *personalization, size_t personalization_size)
{
	drbg_ctx *drbg = (drbg_ctx *)ptr;
	size_t drbg_size = drbg_ctx_size(type, algorithm);
	size_t ctx_size = drbg_size - sizeof(drbg_ctx);

	if (drbg_size == 0)
	{
		return NULL;
	}

	if (size < drbg_size)
	{
		return NULL;
	}

	if (personalization_size > MAX_PERSONALIZATION_SIZE)
	{
		return NULL;
	}

	memset(drbg, 0, drbg_size);

	return drbg_init_checked(ptr, ctx_size, entropy, type, algorithm, reseed_interval, personalization, personalization_size);
}

drbg_ctx *drbg_new(uint32_t (*entropy)(void *buffer, size_t size), drbg_type type, uint32_t algorithm, uint32_t reseed_interval,
				   void *personalization, size_t personalization_size)
{
	void *ptr = NULL;
	drbg_ctx *drbg = NULL;
	size_t ctx_size = 0;
	size_t drbg_size = sizeof(drbg_ctx);

	switch (type)
	{
	case HASH_DRBG:
		ctx_size += hash_drbg_size(algorithm);
		break;
	case HMAC_DRBG:
		ctx_size += hmac_drbg_size(algorithm);
		break;
	case CTR_DRBG:
		ctx_size += ctr_drbg_size(algorithm);
		break;
	default:
		return NULL;
	}

	if (personalization_size > MAX_PERSONALIZATION_SIZE)
	{
		return NULL;
	}

	drbg_size += ctx_size;
	ptr = malloc(drbg_size);

	if (ptr == NULL)
	{
		return NULL;
	}

	memset(ptr, 0, drbg_size);

	drbg = drbg_init_checked(ptr, ctx_size, entropy, type, algorithm, reseed_interval, personalization, personalization_size);

	if (drbg == NULL)
	{
		free(ptr);
		return NULL;
	}

	return drbg;
}

void drbg_delete(drbg_ctx *drbg)
{
	memset(drbg, 0, drbg->drbg_size);
	free(drbg);
}

int32_t drbg_reseed(drbg_ctx *drbg, void *additional_input, size_t input_size)
{
	return drbg->_reseed(drbg->_drbg, additional_input, input_size);
}

int32_t drbg_generate(drbg_ctx *drbg, uint32_t prediction_resistance_request, void *additional_input, size_t input_size, void *output,
					  size_t output_size)
{
	return drbg->_generate(drbg->_drbg, prediction_resistance_request, additional_input, input_size, output, output_size);
}

drbg_ctx *get_default_drbg(void)
{
	if (default_drbg != NULL)
	{
		return default_drbg;
	}

	// Use HMAC DRBG
	default_drbg = drbg_new(NULL, HMAC_DRBG, HMAC_SHA512, 1u << 16, "DEFAULT HMAC DRBG", 17);
	return default_drbg;
}
