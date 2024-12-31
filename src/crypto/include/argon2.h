/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_ARGON2_H
#define CRYPTO_ARGON2_H

#include <stdint.h>

uint32_t argon2d(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
				 uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size);

uint32_t argon2i(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
				 uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size);

uint32_t argon2id(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
				  uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size);

uint32_t argon2ds(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
				  uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size);

#endif
