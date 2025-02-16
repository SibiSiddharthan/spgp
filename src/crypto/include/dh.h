/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DH_H
#define CRYPTO_DH_H

#include <crypt.h>
#include <bignum.h>

typedef struct _dh_key
{
	uint16_t p_bits, q_bits;
	bignum_t *p, *q, *g;
	bignum_t *x, *y;
	bignum_t *mu;
	bignum_ctx *bctx;
} dh_key;

#endif
