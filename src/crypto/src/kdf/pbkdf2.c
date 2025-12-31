/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <crypt.h>

#include <pbkdf2.h>
#include <hmac.h>

#include <stdlib.h>
#include <string.h>


// See NIST SP 800-132 Recommendation for Password-Based Key Derivation

uint32_t pbkdf2(hash_algorithm algorithm, void *password, size_t password_size, void *salt, size_t salt_size, uint32_t iteration_count,
				void *key, size_t key_size)
{
	hmac_ctx *hctx = NULL;
	byte_t *buffer[2048];
	byte_t *pk = key;
	byte_t mac[MAX_HASH_SIZE];
	byte_t mk[MAX_HASH_SIZE];

	uint32_t result = 0;
	uint32_t count = 0;

	if (key_size > (1ull << 32))
	{
		return 0;
	}

	// Initialize hmac_ctx
	hctx = hmac_init(buffer, 2048, algorithm, password, password_size);

	if (hctx == NULL)
	{
		return 0;
	}

	count = CEIL_DIV(key_size, hctx->hash_size);

	for (uint32_t i = 1; i <= count; ++i)
	{
		uint32_t t = BSWAP_32(i);

		memset(mk, 0, hctx->hash_size);

		// Do the first iteration.
		hmac_update(hctx, salt, salt_size);
		hmac_update(hctx, &t, 4);
		hmac_final(hctx, mac, hctx->hash_size);
		hmac_reset(hctx, NULL, 0);

		for (uint32_t k = 0; k < hctx->hash_size; ++k)
		{
			mk[k] ^= mac[k];
		}

		for (uint32_t j = 1; j < iteration_count; ++j)
		{
			hmac_update(hctx, mac, hctx->hash_size);
			hmac_final(hctx, mac, hctx->hash_size);
			hmac_reset(hctx, NULL, 0);

			for (uint32_t k = 0; k < hctx->hash_size; ++k)
			{
				mk[k] ^= mac[k];
			}
		}

		memcpy(pk + result, mk, MIN(hctx->hash_size, key_size - result));
		result += MIN(hctx->hash_size, key_size - result);
	}

	return key_size;
}
