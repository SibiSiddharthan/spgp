/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BIGNUM_INTERNAL_H
#define CRYPTO_BIGNUM_INTERNAL_H

#include <bignum.h>

// Internal bignum_ctx functions
bignum_ctx *bignum_ctx_init(void *ptr, size_t size);
void bignum_ctx_start(bignum_ctx *bctx, size_t size);
void bignum_ctx_end(bignum_ctx *bctx);
void *bignum_ctx_allocate_raw(bignum_ctx *bctx, size_t size);
bignum_t *bignum_ctx_allocate_bignum(bignum_ctx *bctx, uint32_t bits);

// Internal arithmetic functions
uint8_t bignum_add_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count);
uint8_t bignum_sub_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t count);
void bignum_sqr_words(bn_word_t *r, bn_word_t *a, uint32_t a_words);
void bignum_mul_words(bn_word_t *r, bn_word_t *a, bn_word_t *b, uint32_t a_words, uint32_t b_words);
void bignum_div_words(void *scratch, bn_word_t *dd, bn_word_t *dv, bn_word_t *q, bn_word_t *r, uint32_t dd_words, uint32_t dv_words);

void bignum_uadd(bignum_t *r, bignum_t *a, bignum_t *b, uint32_t min_words, uint32_t total_words);
int32_t bignum_usub(bignum_t *r, bignum_t *a, bignum_t *b, uint32_t min_words, uint32_t total_words);

void bignum_increment(bn_word_t *r, uint32_t count);
void bignum_decrement(bn_word_t *r, uint32_t count);
void bignum_2complement(bn_word_t *r, uint32_t count);

int32_t bignum_cmp_words(bn_word_t *a, bn_word_t *b, uint32_t count);

#endif
