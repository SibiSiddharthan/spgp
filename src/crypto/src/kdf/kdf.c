/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <kdf.h>

#include <hmac.h>
#include <cmac.h>
#include <kmac.h>

#include <string.h>

// See NIST SP 800-108 Recommendation for Key Derivation Using Pseudorandom Functions

static uint32_t kdf_counter(kdf_ctx *ctx, void *derived_key, uint32_t derived_key_size)
{
	byte_t *pk = derived_key;

	uint32_t count = CEIL_DIV(derived_key_size, ctx->_out_size);
	uint32_t length = BSWAP_32(derived_key_size * 8);
	uint32_t pos = 0;

	byte_t zero = 0x00;

	// K(i) = PRF (K, [i] || Label || 0x00 || Context || [L])
	// OR
	// K(i) = PRF (K, [i] || Input)

	for (uint32_t i = 1; i <= count; ++i)
	{
		uint32_t t = BSWAP_32(i);

		ctx->_kdf_update(ctx->_ctx, &t, 4);

		if (ctx->flags & KDF_FIXED_DATA)
		{
			ctx->_kdf_update(ctx->_ctx, ctx->fixed, ctx->fixed_size);
		}
		else
		{
			if (ctx->label != NULL)
			{
				ctx->_kdf_update(ctx->_ctx, ctx->label, ctx->label_size);
			}

			ctx->_kdf_update(ctx->_ctx, &zero, 1);

			if (ctx->context != NULL)
			{
				ctx->_kdf_update(ctx->_ctx, ctx->context, ctx->context_size);
			}

			ctx->_kdf_update(ctx->_ctx, &length, 4);
		}

		ctx->_kdf_final(ctx->_ctx, pk + pos, MIN(ctx->_out_size, derived_key_size - pos));
		pos += MIN(ctx->_out_size, derived_key_size - pos);

		ctx->_kdf_reset(ctx->_ctx, NULL, 0);
	}

	return derived_key_size;
}

static uint32_t kdf_feedback(kdf_ctx *ctx, void *derived_key, uint32_t derived_key_size)
{
	byte_t *pk = derived_key;

	uint32_t count = CEIL_DIV(derived_key_size, ctx->_out_size);
	uint32_t length = BSWAP_32(derived_key_size * 8);
	uint32_t pos = 0;

	byte_t zero = 0x00;
	byte_t mac[MAX_HASH_SIZE] = {0};

	// K(0) = IV
	// K(i) = PRF (K, K(i−1) || [i] || Label || 0x00 || Context || [L])
	// OR
	// K(i) = PRF (K, K(i−1) || [i] || Input)

	for (uint32_t i = 1; i <= count; ++i)
	{
		uint32_t t = BSWAP_32(i);

		if (i == 1)
		{
			if (ctx->iv != NULL)
			{
				ctx->_kdf_update(ctx->_ctx, ctx->iv, ctx->iv_size);
			}
		}
		else
		{
			ctx->_kdf_update(ctx->_ctx, mac, ctx->_out_size);
		}

		ctx->_kdf_update(ctx->_ctx, &t, 4);

		if (ctx->flags & KDF_FIXED_DATA)
		{
			ctx->_kdf_update(ctx->_ctx, ctx->fixed, ctx->fixed_size);
		}
		else
		{
			if (ctx->label != NULL)
			{
				ctx->_kdf_update(ctx->_ctx, ctx->label, ctx->label_size);
			}

			ctx->_kdf_update(ctx->_ctx, &zero, 1);

			if (ctx->context != NULL)
			{
				ctx->_kdf_update(ctx->_ctx, ctx->context, ctx->context_size);
			}

			ctx->_kdf_update(ctx->_ctx, &length, 4);
		}

		ctx->_kdf_final(ctx->_ctx, mac, ctx->_out_size);

		memcpy(pk + pos, mac, MIN(ctx->_out_size, derived_key_size - pos));
		pos += MIN(ctx->_out_size, derived_key_size - pos);

		ctx->_kdf_reset(ctx->_ctx, NULL, 0);
	}

	return derived_key_size;
}

static uint32_t kdf_double_pipeline(kdf_ctx *ctx, void *derived_key, uint32_t derived_key_size)
{
	byte_t *pk = derived_key;

	uint32_t count = CEIL_DIV(derived_key_size, ctx->_out_size);
	uint32_t length = BSWAP_32(derived_key_size * 8);
	uint32_t pos = 0;

	byte_t zero = 0x00;
	byte_t mac[MAX_HASH_SIZE] = {0};

	// A(0) = Label || 0x00 || Context || [L]
	// OR
	// A(0) = Input
	// A(i) = PRF (K, A(i−1))
	// K(i) = PRF (K, A(i) || [i] || Label || 0x00 || Context || [L])
	// OR
	// K(i) = PRF (K, A(i) || [i] || Input)
	for (uint32_t i = 1; i <= count; ++i)
	{
		uint32_t t = BSWAP_32(i);

		if (i == 1)
		{
			// Calculate A0
			if (ctx->flags & KDF_FIXED_DATA)
			{
				ctx->_kdf_update(ctx->_ctx, ctx->fixed, ctx->fixed_size);
			}
			else
			{
				if (ctx->label != NULL)
				{
					ctx->_kdf_update(ctx->_ctx, ctx->label, ctx->label_size);
				}

				ctx->_kdf_update(ctx->_ctx, &zero, 1);

				if (ctx->context != NULL)
				{
					ctx->_kdf_update(ctx->_ctx, ctx->context, ctx->context_size);
				}

				ctx->_kdf_update(ctx->_ctx, &length, 4);
			}

			ctx->_kdf_final(ctx->_ctx, mac, ctx->_out_size);
			ctx->_kdf_reset(ctx->_ctx, NULL, 0);
		}
		else
		{
			ctx->_kdf_update(ctx->_ctx, mac, ctx->_out_size);
			ctx->_kdf_final(ctx->_ctx, mac, ctx->_out_size);
			ctx->_kdf_reset(ctx->_ctx, NULL, 0);
		}

		ctx->_kdf_update(ctx->_ctx, mac, ctx->_out_size);
		ctx->_kdf_update(ctx->_ctx, &t, 4);

		if (ctx->flags & KDF_FIXED_DATA)
		{
			ctx->_kdf_update(ctx->_ctx, ctx->fixed, ctx->fixed_size);
		}
		else
		{

			if (ctx->label != NULL)
			{
				ctx->_kdf_update(ctx->_ctx, ctx->label, ctx->label_size);
			}

			ctx->_kdf_update(ctx->_ctx, &zero, 1);

			if (ctx->context != NULL)
			{
				ctx->_kdf_update(ctx->_ctx, ctx->context, ctx->context_size);
			}

			ctx->_kdf_update(ctx->_ctx, &length, 4);
		}

		ctx->_kdf_final(ctx->_ctx, pk + pos, MIN(ctx->_out_size, derived_key_size - pos));
		pos += MIN(ctx->_out_size, derived_key_size - pos);

		ctx->_kdf_reset(ctx->_ctx, NULL, 0);
	}

	return derived_key_size;
}

uint32_t kdf(kdf_ctx *ctx, void *key, uint32_t key_size, void *derived_key, uint32_t derived_key_size)
{
	byte_t buffer[2048] = {0};

	switch (ctx->prf)
	{
	case KDF_PRF_CMAC:
	{
		ctx->_ctx = cmac_init(buffer, 2048, ctx->algorithm, key, key_size);

		if (ctx->_ctx == NULL)
		{
			return 0;
		}

		ctx->_kdf_update = (void (*)(void *, void *, size_t))cmac_update;
		ctx->_kdf_final = (void (*)(void *, void *, size_t))cmac_final;
		ctx->_kdf_reset = (void (*)(void *, void *, size_t))cmac_reset;
		ctx->_out_size = ((cmac_ctx *)ctx)->block_size;
	}
	break;
	case KDF_PRF_HMAC:
	{
		ctx->_ctx = hmac_init(buffer, 2048, ctx->algorithm, key, key_size);

		if (ctx->_ctx == NULL)
		{
			return 0;
		}

		ctx->_kdf_update = (void (*)(void *, void *, size_t))hmac_update;
		ctx->_kdf_final = (void (*)(void *, void *, size_t))hmac_final;
		ctx->_kdf_reset = (void (*)(void *, void *, size_t))hmac_reset;
		ctx->_out_size = ((hmac_ctx *)ctx)->hash_size;
	}
	break;
	case KDF_PRF_KMAC:
	{
		if (ctx->algorithm == KMAC_128)
		{
			kmac128(key, key_size, ctx->label, ctx->label_size, ctx->context, ctx->context_size, derived_key, derived_key_size);
			return derived_key_size;
		}

		if (ctx->algorithm == KMAC_256)
		{
			kmac256(key, key_size, ctx->label, ctx->label_size, ctx->context, ctx->context_size, derived_key, derived_key_size);
			return derived_key_size;
		}

		// error
		return 0;
	}
	break;
	}

	switch (ctx->mode)
	{
	case KDF_MODE_COUNTER:
		return kdf_counter(ctx, derived_key, derived_key_size);
	case KDF_MODE_FEEDBACK:
		return kdf_feedback(ctx, derived_key, derived_key_size);
	case KDF_MODE_DOUBLE_PIPLELINE:
		return kdf_double_pipeline(ctx, derived_key, derived_key_size);
	}
}
