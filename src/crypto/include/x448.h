/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_X448_H
#define CRYPTO_X448_H

#include <crypt.h>

#define X448_OCTET_SIZE 56
#define X448_BITS       448

typedef struct _x448_key
{
	byte_t private_key[X448_OCTET_SIZE];
	byte_t public_key[X448_OCTET_SIZE];
} x448_key;

uint32_t x448_key_generate(x448_key *key);
void x448(byte_t v[X448_OCTET_SIZE], byte_t u[X448_OCTET_SIZE], byte_t k[X448_OCTET_SIZE]);

#endif
