/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_PBKDF2_H
#define CRYPTO_PBKDF2_H

#include <stdint.h>
#include <hmac.h>

uint32_t pbkdf2(hash_algorithm algorithm, void *password, size_t password_size, void *salt, size_t salt_size, uint32_t iteration_count,
				void *key, size_t key_size);

#endif
