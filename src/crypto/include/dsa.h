/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DSA_H
#define CRYPTO_DSA_H

#include <bignum.h>
#include <types.h>

typedef struct _dsa_key
{
	bignum_t *p, *q, *g;
	bignum_t *x, *y;
} dsa_key;

typedef struct _dsa_signature
{
	bignum_t *r, *s;
} dsa_signature;

dsa_key *dsa_generate_key(uint32_t bits);
void dsa_delete_key(dsa_key *key);

dsa_signature *dsa_sign(dsa_key *key, byte_t *message, size_t size);
int32_t dsa_verify(dsa_key *key, dsa_signature *signature, byte_t *message, size_t size);

#endif
