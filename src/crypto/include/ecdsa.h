/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_ECDSA_H
#define CRYPTO_ECDSA_H

#include <crypt.h>
#include <bignum.h>
#include <ec.h>
#include <hash.h>

typedef struct _ecdsa_signature
{
	bignum_t *r, *s;
} ecdsa_signature;

ecdsa_signature *ecdsa_sign(ec_key *key, void *salt, size_t salt_size, void *hash, size_t hash_size, void *signature,
							size_t signature_size);
uint32_t ecdsa_verify(ec_key *key, ecdsa_signature *ecsign, void *hash, size_t hash_size);

#endif
