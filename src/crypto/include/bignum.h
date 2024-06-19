/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BIGNUM_H
#define CRYPTO_BIGNUM_H

#include <stdint.h>
#include <types.h>

#define BIGNUM_WORD_SIZE     8
#define BIGNUM_BITS_PER_WORD (8 * BIGNUM_WORD_SIZE)

typedef uint64_t bn_word_t;

typedef struct _bignum_t
{
	uint32_t bits;
	uint32_t size;
	int16_t sign;
	int16_t resize;
	bn_word_t *words;
} bignum_t;

size_t bignum_size(uint32_t bits);

bignum_t *bignum_init(void *ptr, size_t size, uint32_t bits);
bignum_t *bignum_new(uint32_t bits);
bignum_t *bignum_copy(void *ptr, size_t size, bignum_t *bn);
bignum_t *bignum_dup(bignum_t *bn);
void bignum_free(bignum_t *bn);

bignum_t *bignum_set_bytes_le(bignum_t *bn, byte_t *bytes, size_t size);
bignum_t *bignum_set_bytes_be(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_get_bytes_le(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_get_bytes_be(bignum_t *bn, byte_t *bytes, size_t size);

bignum_t *bignum_set_hex(bignum_t *bn, char *hex, size_t size);
int32_t bignum_get_hex(bignum_t *bn, char *hex, size_t size);

void bignum_zero(bignum_t *bn);
void bignum_set(bignum_t *bn, bn_word_t value);
uint32_t bignum_bitcount(bignum_t *bn);

int32_t bignum_cmp(bignum_t *a, bignum_t *b);
int32_t bignum_cmp_abs(bignum_t *a, bignum_t *b);

bignum_t *bignum_rand(bignum_t *bn, uint32_t bits);

bignum_t *bignum_add(bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_sub(bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_mul(bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_div(bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_mod(bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_modadd(bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m);
bignum_t *bignum_modmul(bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m);
bignum_t *bignum_modexp(bignum_t *r, bignum_t *a, bignum_t *p, bignum_t *m);
bignum_t *bignum_modinv(bignum_t *r, bignum_t *a, bignum_t *p);

int32_t bignum_divmod(bignum_t *dd, bignum_t *dv, bignum_t **q, bignum_t **r);

#endif
