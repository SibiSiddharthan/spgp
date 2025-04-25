/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DSA_H
#define CRYPTO_DSA_H

#include <crypt.h>
#include <bignum.h>
#include <hash.h>
#include <dh.h>

typedef dh_group dsa_group;
typedef dh_key dsa_key;

typedef struct _dsa_signature
{
	struct
	{
		uint32_t bits;
		uint32_t size;
		byte_t *sign;
	} r, s;
} dsa_signature;

dsa_key *dsa_key_generate(dsa_group *group, bignum_t *x);
dsa_key *dsa_key_new(dsa_group *group, bignum_t *x, bignum_t *y);
void dsa_key_delete(dsa_key *key);

dsa_signature *dsa_signature_new(dsa_key *key);
void dsa_signature_delete(dsa_signature *sign);

dsa_signature *dsa_sign(dsa_key *key, dsa_signature *dsign, void *salt, size_t salt_size, void *hash, size_t hash_size);
uint32_t dsa_verify(dsa_key *key, dsa_signature *dsign, void *hash, size_t hash_size);

#endif
