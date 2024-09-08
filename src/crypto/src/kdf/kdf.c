/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <kdf.h>
#include <hmac.h>
#include <cmac.h>
#include <kmac.h>

#include <byteswap.h>
#include <minmax.h>
#include <round.h>

// See NIST SP 800-108 Recommendation for Key Derivation Using Pseudorandom Functions

uint32_t kdf_counter(kdf_prf prf, uint32_t algorithm, void *key, uint32_t key_size, void *label, uint32_t label_size, void *context,
					 uint32_t context_size, void *derived_key, uint32_t derived_key_size)
{
	void *ctx = NULL;
	byte_t *pk = derived_key;
	byte_t buffer[2048];

	uint32_t out_size = 0;
	uint32_t count = 0;
	uint32_t pos = 0;

	ctx = buffer;
	void (*kdf_update)(void *, void *, size_t) = NULL;
	void (*kdf_final)(void *, void *, size_t) = NULL;
	void (*kdf_reset)(void *, void *, size_t) = NULL;

	switch (prf)
	{
	case KDF_PRF_CMAC:
		ctx = cmac_init(ctx, 2048, algorithm, key, key_size);
		kdf_update = (void (*)(void *, void *, size_t))cmac_update;
		kdf_final = (void (*)(void *, void *, size_t))cmac_final;
		kdf_reset = (void (*)(void *, void *, size_t))cmac_reset;
		out_size = 16;
		break;
	case KDF_PRF_HMAC:
		ctx = hmac_init(ctx, 2048, algorithm, key, key_size);
		kdf_update = (void (*)(void *, void *, size_t))hmac_update;
		kdf_final = (void (*)(void *, void *, size_t))hmac_final;
		kdf_reset = (void (*)(void *, void *, size_t))hmac_reset;
		out_size = ((hmac_ctx *)ctx)->hash_size;
		break;
	}

	if (ctx == NULL)
	{
		return 0;
	}

	count = CEIL_DIV(derived_key_size, out_size);

	uint32_t l = BSWAP_32(derived_key_size * 8);
	byte_t z = 0x00;

	// K(i) = PRF (K, [i] || Label || 0x00 || Context || [L])
	for (uint32_t i = 1; i <= count; ++i)
	{
		uint32_t t = BSWAP_32(i);

		kdf_update(ctx, &t, 4);

		if (label != NULL)
		{
			kdf_update(ctx, label, label_size);
		}

		kdf_update(ctx, &z, 1);

		if (context != NULL)
		{
			kdf_update(ctx, context, context_size);
		}

		kdf_update(ctx, &l, 4);

		kdf_final(ctx, pk + pos, MIN(out_size, derived_key_size - pos));
		pos += MIN(out_size, derived_key_size - pos);

		kdf_reset(ctx, NULL, 0);
	}

	return derived_key_size;
}

uint32_t kdf_feedback(kdf_prf prf, uint32_t algorithm, void *key, uint32_t key_size, void *label, uint32_t label_size, void *context,
					  uint32_t context_size, void *iv, uint32_t iv_size, void *derived_key, uint32_t derived_key_size)
{
	void *ctx = NULL;
	byte_t *pk = derived_key;
	byte_t buffer[2048];
	byte_t mac[MAX_HASH_SIZE];

	uint32_t out_size = 0;
	uint32_t count = 0;
	uint32_t pos = 0;

	ctx = buffer;
	void (*kdf_update)(void *, void *, size_t) = NULL;
	void (*kdf_final)(void *, void *, size_t) = NULL;
	void (*kdf_reset)(void *, void *, size_t) = NULL;

	switch (prf)
	{
	case KDF_PRF_CMAC:
		ctx = cmac_init(ctx, 2048, algorithm, key, key_size);
		kdf_update = (void (*)(void *, void *, size_t))cmac_update;
		kdf_final = (void (*)(void *, void *, size_t))cmac_final;
		kdf_reset = (void (*)(void *, void *, size_t))cmac_reset;
		out_size = 16;
		break;
	case KDF_PRF_HMAC:
		ctx = hmac_init(ctx, 2048, algorithm, key, key_size);
		kdf_update = (void (*)(void *, void *, size_t))hmac_update;
		kdf_final = (void (*)(void *, void *, size_t))hmac_final;
		kdf_reset = (void (*)(void *, void *, size_t))hmac_reset;
		out_size = ((hmac_ctx *)ctx)->hash_size;
		break;
	}

	if (ctx == NULL)
	{
		return 0;
	}

	count = CEIL_DIV(derived_key_size, out_size);

	uint32_t l = BSWAP_32(derived_key_size * 8);
	byte_t z = 0x00;

	// K(0) = IV
	// K(i) = PRF (K, K(i−1) || [i] || Label || 0x00 || Context || [L])
	for (uint32_t i = 1; i <= count; ++i)
	{
		uint32_t t = BSWAP_32(i);

		if (i == 0)
		{
			if (iv != NULL)
			{
				kdf_update(ctx, iv, iv_size);
			}
		}
		else
		{
			kdf_update(ctx, mac, out_size);
		}

		kdf_update(ctx, &t, 4);

		if (label != NULL)
		{
			kdf_update(ctx, label, label_size);
		}

		kdf_update(ctx, &z, 1);

		if (context != NULL)
		{
			kdf_update(ctx, context, context_size);
		}

		kdf_update(ctx, &l, 4);

		kdf_final(ctx, mac, out_size);

		memcpy(pk + pos, mac, MIN(out_size, derived_key_size - pos));
		pos += MIN(out_size, derived_key_size - pos);

		kdf_reset(ctx, NULL, 0);
	}

	return derived_key_size;
}

uint32_t kdf_double_pipeline(kdf_prf prf, uint32_t algorithm, void *key, uint32_t key_size, void *label, uint32_t label_size, void *context,
							 uint32_t context_size, void *derived_key, uint32_t derived_key_size)
{
	void *ctx = NULL;
	byte_t *pk = derived_key;
	byte_t buffer[2048];
	byte_t mac[MAX_HASH_SIZE];

	uint32_t out_size = 0;
	uint32_t count = 0;
	uint32_t pos = 0;

	ctx = buffer;
	void (*kdf_update)(void *, void *, size_t) = NULL;
	void (*kdf_final)(void *, void *, size_t) = NULL;
	void (*kdf_reset)(void *, void *, size_t) = NULL;

	switch (prf)
	{
	case KDF_PRF_CMAC:
		ctx = cmac_init(ctx, 2048, algorithm, key, key_size);
		kdf_update = (void (*)(void *, void *, size_t))cmac_update;
		kdf_final = (void (*)(void *, void *, size_t))cmac_final;
		kdf_reset = (void (*)(void *, void *, size_t))cmac_reset;
		out_size = 16;
		break;
	case KDF_PRF_HMAC:
		ctx = hmac_init(ctx, 2048, algorithm, key, key_size);
		kdf_update = (void (*)(void *, void *, size_t))hmac_update;
		kdf_final = (void (*)(void *, void *, size_t))hmac_final;
		kdf_reset = (void (*)(void *, void *, size_t))hmac_reset;
		out_size = ((hmac_ctx *)ctx)->hash_size;
		break;
	}

	if (ctx == NULL)
	{
		return 0;
	}

	count = CEIL_DIV(derived_key_size, out_size);

	uint32_t l = BSWAP_32(derived_key_size * 8);
	byte_t z = 0x00;

	// A(0) = Label || 0x00 || Context || [L]
	// A(i) = PRF (K, A(i−1))
	// K(i) = PRF (K, A(i) || [i] || Label || 0x00 || Context || [L])
	for (uint32_t i = 1; i <= count; ++i)
	{
		uint32_t t = BSWAP_32(i);

		if (i == 0)
		{
			// Calculate A0
			if (label != NULL)
			{
				kdf_update(ctx, label, label_size);
			}

			kdf_update(ctx, &z, 1);

			if (context != NULL)
			{
				kdf_update(ctx, context, context_size);
			}

			kdf_update(ctx, &l, 4);

			kdf_final(ctx, mac, out_size);
			kdf_reset(ctx, NULL, 0);
		}
		else
		{
			kdf_update(ctx, mac, out_size);
			kdf_final(ctx, mac, out_size);
			kdf_reset(ctx, NULL, 0);
		}

		kdf_update(ctx, mac, out_size);
		kdf_update(ctx, &t, 4);

		if (label != NULL)
		{
			kdf_update(ctx, label, label_size);
		}

		kdf_update(ctx, &z, 1);

		if (context != NULL)
		{
			kdf_update(ctx, context, context_size);
		}

		kdf_update(ctx, &l, 4);

		kdf_final(ctx, pk + pos, MIN(out_size, derived_key_size - pos));
		pos += MIN(out_size, derived_key_size - pos);

		kdf_reset(ctx, NULL, 0);
	}

	return derived_key_size;
}

uint32_t kdf(kdf_mode mode, kdf_prf prf, uint32_t algorithm, void *key, uint32_t key_size, void *label, uint32_t label_size, void *context,
			 uint32_t context_size, void *iv, uint32_t iv_size, void *derived_key, uint32_t derived_key_size)
{
	switch (mode)
	{
	case KDF_MODE_COUNTER:
		return kdf_counter(prf, algorithm, key, key_size, label, label_size, context, context_size, derived_key, derived_key_size);
	case KDF_MODE_FEEDBACK:
		return kdf_feedback(prf, algorithm, key, key_size, label, label_size, context, context_size, iv, iv_size, derived_key,
							derived_key_size);
	case KDF_MODE_DOUBLE_PIPLELINE:
		return kdf_double_pipeline(prf, algorithm, key, key_size, label, label_size, context, context_size, derived_key, derived_key_size);
	}
}
