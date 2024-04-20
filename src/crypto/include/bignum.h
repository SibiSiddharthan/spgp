/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BIGNUM_H
#define CRYPTO_BIGNUM_H

#include <stdint.h>
#include <types.h>

typedef struct _bignum
{
	uint32_t bits;
	uint32_t size;
	uint64_t *qwords;
} bignum_t;

bignum_t *bignum_new(uint32_t bits);
void bignum_free(bignum_t *bn);
void bignum_secure_free(bignum_t *bn);

void bignum_set(bignum_t *bn, uint64_t value);

int32_t bignum_set_bytes_le(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_set_bytes_be(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_get_bytes_le(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_get_bytes_be(bignum_t *bn, byte_t *bytes, size_t size);

bignum_t *bignum_add(bignum_t *a, bignum_t *b);

#endif
