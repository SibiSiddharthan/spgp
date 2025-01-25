/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_X25519_H
#define CRYPTO_X25519_H

#include <types.h>

#define X25519_OCTET_SIZE 32
#define X25519_BITS       255

typedef struct _x25519_key
{
	byte_t private_key[X25519_OCTET_SIZE];
	byte_t public_key[X25519_OCTET_SIZE];
} x25519_key;

void x25519_key_generate(x25519_key *key);
void x25519(byte_t v[X25519_OCTET_SIZE], byte_t u[X25519_OCTET_SIZE], byte_t k[X25519_OCTET_SIZE]);

#endif
