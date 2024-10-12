/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BIGNUM_H
#define CRYPTO_BIGNUM_H

#include <types.h>
#include <minmax.h>
#include <round.h>

#define BIGNUM_WORD_SIZE     8
#define BIGNUM_BITS_PER_WORD (8 * BIGNUM_WORD_SIZE)

#define BIGNUM_WORD_COUNT(BN) (CEIL_DIV((BN)->bits, BIGNUM_BITS_PER_WORD))

#define BIGNUM_FLAG_NO_RESIZE 0x1
#define BIGNUM_FLAG_MASK      0x1

typedef uint64_t bn_word_t;

typedef struct _bignum_t
{
	uint32_t bits;
	uint32_t size;
	int8_t sign;
	int8_t resize;
	uint16_t flags;
	bn_word_t *words;
} bignum_t;

typedef struct _bignum_ctx bignum_ctx;

inline size_t bignum_size(uint32_t bits)
{
	return sizeof(bignum_t) + CEIL_DIV(MAX(bits, 1), BIGNUM_BITS_PER_WORD) * BIGNUM_WORD_SIZE;
}

bignum_t *bignum_init(void *ptr, size_t size, uint32_t bits);
bignum_t *bignum_new(uint32_t bits);
bignum_t *bignum_copy(bignum_t *dst_bn, bignum_t *src_bn);
bignum_t *bignum_dup(bignum_ctx *bctx, bignum_t *bn);
bignum_t *bignum_resize(bignum_t *bn, uint32_t bits);
void bignum_delete(bignum_t *bn);

bignum_t *bignum_set_bytes_le(bignum_t *bn, byte_t *bytes, size_t size);
bignum_t *bignum_set_bytes_be(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_get_bytes_le(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_get_bytes_be(bignum_t *bn, byte_t *bytes, size_t size);
int32_t bignum_get_bytes_be_padded(bignum_t *bn, byte_t *bytes, size_t size);

bignum_t *bignum_set_hex(bignum_t *bn, char *hex, size_t size);
int32_t bignum_get_hex(bignum_t *bn, char *hex, size_t size);

void bignum_zero(bignum_t *bn);
void bignum_one(bignum_t *bn);
void bignum_set_word(bignum_t *bn, bn_word_t value);
void bignum_set_sign(bignum_t *bn, int8_t sign);
void bignum_set_flags(bignum_t *bn, int16_t flags);
uint32_t bignum_bitcount(bignum_t *bn);
uint32_t bignum_ctz(bignum_t *bn);

int32_t bignum_cmp(bignum_t *a, bignum_t *b);
int32_t bignum_cmp_abs(bignum_t *a, bignum_t *b);

bignum_t *bignum_rand(bignum_t *bn, void *drbg, uint32_t bits);
bignum_t *bignum_prime(bignum_t *bn, uint32_t bits);

int32_t bignum_is_probable_prime(bignum_ctx *bctx, bignum_t *bn);

bignum_t *bignum_add(bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_sub(bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_mul(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_sqr(bignum_ctx *bctx, bignum_t *r, bignum_t *a);
bignum_t *bignum_div(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_mod(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b);

bignum_t *bignum_lshift(bignum_t *r, bignum_t *a, uint32_t shift);
bignum_t *bignum_rshift(bignum_t *r, bignum_t *a, uint32_t shift);

bignum_t *bignum_modadd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m);
bignum_t *bignum_modsub(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m);
bignum_t *bignum_modmul(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b, bignum_t *m);
bignum_t *bignum_modsqr(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *m);
bignum_t *bignum_modsqrt(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *m);
bignum_t *bignum_modexp(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *p, bignum_t *m);
bignum_t *bignum_modinv(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *m);

bignum_t *bignum_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_euclid_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b);
bignum_t *bignum_binary_gcd(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *b);

int32_t bignum_gcdex(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b);
int32_t bignum_euclid_gcdex(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b);
int32_t bignum_binary_gcdex(bignum_ctx *bctx, bignum_t *r, bignum_t *u, bignum_t *v, bignum_t *a, bignum_t *b);

int32_t bignum_divmod(bignum_ctx *bctx, bignum_t *dd, bignum_t *dv, bignum_t *q, bignum_t *r);

int32_t bignum_barret_udivmod(bignum_ctx *bctx, bignum_t *dd, bignum_t *dv, bignum_t *mu, bignum_t *q, bignum_t *r);
bignum_t *bignum_barret_modexp(bignum_ctx *bctx, bignum_t *r, bignum_t *a, bignum_t *p, bignum_t *m, bignum_t *mu);

// Functions for bignum_ctx.

bignum_ctx *bignum_ctx_new(size_t size);
void bignum_ctx_delete(bignum_ctx *bctx);

#endif
