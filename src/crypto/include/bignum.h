/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BIGNUM_H
#define CRYPTO_BIGNUM_H

#include <stdint.h>

typedef struct _bignum
{
	uint32_t bits;
	uint32_t size;
	uint64_t qwords[1];
} bignum_t;

#endif
