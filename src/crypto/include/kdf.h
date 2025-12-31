/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_KDF_H
#define CRYPTO_KDF_H

#include <stdint.h>
#include <kmac.h>

typedef enum _kdf_prf
{
	KDF_PRF_CMAC = 1,
	KDF_PRF_HMAC,
	KDF_PRF_KMAC
} kdf_prf;

typedef enum _kdf_mode
{
	KDF_MODE_COUNTER = 1,
	KDF_MODE_FEEDBACK,
	KDF_MODE_DOUBLE_PIPLELINE
} kdf_mode;

typedef enum _kdf_counter_bits
{
	KDF_COUNTER_8 = 1,
	KDF_COUNTER_16,
	KDF_COUNTER_24,
	KDF_COUNTER_32
} kdf_counter_bits;

typedef enum _kdf_counter_location
{
	KDF_COUNTER_BEFORE = 1,
	KDF_COUNTER_AFTER,
	KDF_COUNTER_MIDDLE
} kdf_counter_location;

#define KDF_NO_COUNTER 0x1
#define KDF_FIXED_DATA 0x2

typedef byte_t kdf_flags;
typedef byte_t kdf_algorithm;

typedef struct _kdf_ctx
{
	kdf_prf prf;
	kdf_mode mode;
	kdf_algorithm algorithm;
	kdf_counter_bits counter;
	kdf_flags flags;

	union
	{
		struct
		{
			kdf_counter_location location;

			struct
			{
				void *input;
				uint32_t input_size;
				uint32_t prefix_size;
			};
		};

		struct
		{
			void *label;
			void *context;

			uint32_t label_size;
			uint32_t context_size;
		};
	};

	void *iv;
	uint32_t iv_size;

	void *_kdf;
	void (*_kdf_update)(void *, void *, size_t);
	void (*_kdf_final)(void *, void *, size_t);
	void (*_kdf_reset)(void *, void *, size_t);
	uint32_t _out_size;

} kdf_ctx;

uint32_t kdf(kdf_ctx *ctx, void *key, uint32_t key_size, void *derived_key, uint32_t derived_key_size);

#endif
