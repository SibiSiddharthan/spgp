/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_HKDF_H
#define CRYPTO_HKDF_H

#include <stdint.h>
#include <hmac.h>

// Refer RFC 5869 : HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

uint32_t hkdf(hash_algorithm algorithm, void *key, uint32_t key_size, void *salt, size_t salt_size, void *info, size_t info_size,
			  void *derived_key, uint32_t derived_key_size);

#endif
