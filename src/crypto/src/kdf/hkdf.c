/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <hkdf.h>
#include <hmac.h>

#include <minmax.h>
#include <round.h>

// Refer RFC 5869 : HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

uint32_t hkdf(hash_algorithm algorithm, void *key, uint32_t key_size, void *salt, size_t salt_size, void *info, size_t info_size,
			  void *derived_key, uint32_t derived_key_size)
{
	hmac_ctx *hctx = NULL;
	byte_t *pk = derived_key;

	byte_t buffer[2048];
	byte_t prk[MAX_HASH_SIZE];
	byte_t mac[MAX_HASH_SIZE];

	uint32_t count = 0;
	uint32_t pos = 0;

	hctx = hmac_init(buffer, 2048, algorithm, salt, salt_size);

	if (hctx == NULL)
	{
		return 0;
	}

	// Extract
	// PRK = HMAC-Hash(salt, key)
	hmac_update(hctx, key, key_size);
	hmac_final(hctx, prk, hctx->hash_size);

	// Expand
	// OKM = T[1] || T[2] ...
	// T[0] = empty
	// T[i] = HMAC-Hash(PRK, T[i-1] || info || i)
	count = CEIL_DIV(derived_key_size, hctx->hash_size);

	if (count > 255)
	{
		return 0;
	}

	// Reset with prk as the key
	hmac_reset(hctx, prk, hctx->hash_size);

	for (uint8_t i = 1; i <= count; ++i)
	{
		if (i > 1)
		{
			hmac_update(hctx, mac, hctx->hash_size);
		}

		if (info != NULL)
		{
			hmac_update(hctx, info, info_size);
		}

		hmac_update(hctx, &i, 1);
		hmac_final(hctx, mac, hctx->hash_size);

		memcpy(pk + pos, mac, MIN(hctx->hash_size, derived_key_size - pos));
		pos += MIN(hctx->hash_size, derived_key_size - pos);

		hmac_reset(hctx, NULL, 0);
	}

	return derived_key_size;
}
