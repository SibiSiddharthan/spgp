/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_X448_H
#define CRYPTO_X448_H

#include <crypt.h>

#define X448_KEY_OCTETS 56
#define X448_BITS       448

typedef struct _x448_key
{
	byte_t private_key[X448_KEY_OCTETS];
	byte_t public_key[X448_KEY_OCTETS];
} x448_key;

x448_key *x448_key_generate(x448_key *key, byte_t secret[X448_KEY_OCTETS]);
void x448(byte_t v[X448_KEY_OCTETS], byte_t u[X448_KEY_OCTETS], byte_t k[X448_KEY_OCTETS]);

#endif
