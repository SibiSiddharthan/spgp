/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BIGNUM_INTERNAL_H
#define CRYPTO_BIGNUM_INTERNAL_H

#include <bignum.h>

bignum_ctx *bignum_ctx_init(void *ptr, size_t size);
void bignum_ctx_start(bignum_ctx *bctx, size_t size);
void bignum_ctx_end(bignum_ctx *bctx);
void *bignum_ctx_allocate_raw(bignum_ctx *bctx, size_t size);
bignum_t *bignum_ctx_allocate_bignum(bignum_ctx *bctx, uint32_t bits);



#endif
