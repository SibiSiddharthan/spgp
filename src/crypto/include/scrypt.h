/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_SCRYPT_H
#define CRYPTO_SCRYPT_H

#include <stdint.h>

uint32_t scrypt(void *password, size_t password_size, void *salt, size_t salt_size, uint32_t n, uint32_t p, uint32_t r, void *key,
				size_t key_size);

#endif
