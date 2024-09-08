/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_KDF_H
#define CRYPTO_KDF_H

#include <stdint.h>
#include <kmac.h>

typedef enum _kdf_prf
{
	KDF_PRF_CMAC,
	KDF_PRF_HMAC
} kdf_prf;

typedef enum _kdf_mode
{
	KDF_MODE_COUNTER,
	KDF_MODE_FEEDBACK,
	KDF_MODE_DOUBLE_PIPLELINE
} kdf_mode;

uint32_t kdf(kdf_mode mode, kdf_prf prf, uint32_t algorithm, void *key, uint32_t key_size, void *label, uint32_t label_size, void *context,
			 uint32_t context_size, void *iv, uint32_t iv_size, void *derived_key, uint32_t derived_key_size);

inline uint32_t kdf_kmac128(void *key, uint32_t key_size, void *context, uint32_t context_size, void *label, uint32_t label_size,
							void *derived_key, uint32_t derived_key_size)
{
	kmac128(key, key_size, label, label_size, context, context_size, derived_key, derived_key_size);
	return derived_key_size;
}

inline uint32_t kdf_kmac256(void *key, uint32_t key_size, void *label, uint32_t label_size, void *context, uint32_t context_size,
							void *derived_key, uint32_t derived_key_size)
{
	kmac256(key, key_size, label, label_size, context, context_size, derived_key, derived_key_size);
	return derived_key_size;
}

#endif
