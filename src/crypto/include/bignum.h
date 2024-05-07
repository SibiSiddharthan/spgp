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
bignum_t *bignum_new_rand(uint32_t bits);
void bignum_free(bignum_t *bn);
void bignum_secure_free(bignum_t *bn);

void bignum_set(bignum_t *bn, uint64_t value);

int32_t bignum_set_bytes_le(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_set_bytes_be(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_get_bytes_le(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_get_bytes_be(bignum_t *bn, byte_t *bytes, size_t size);

int32_t bignum_cmp(bignum_t *a, bignum_t *b);

bignum_t *bignum_add(bignum_t *a, bignum_t *b);
bignum_t *bignum_sub(bignum_t *a, bignum_t *b);
bignum_t *bignum_mul(bignum_t *a, bignum_t *b);
bignum_t *bignum_div(bignum_t *a, bignum_t *b);
bignum_t *bignum_mod(bignum_t *a, bignum_t *b);
bignum_t *bignum_modadd(bignum_t *a, bignum_t *b, bignum_t *m);
bignum_t *bignum_modmul(bignum_t *a, bignum_t *b, bignum_t *m);
bignum_t *bignum_modexp(bignum_t *a, bignum_t *p, bignum_t *m);
bignum_t *bignum_modinv(bignum_t *a, bignum_t *p);

void bignum_divmod(bignum_t *dd, bignum_t *dv, bignum_t *q, bignum_t *r);

#endif
