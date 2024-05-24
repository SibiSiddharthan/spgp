/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_SHAKE_H
#define CRYPTO_SHAKE_H

#include <sha.h>

shake128_ctx *shake128_init(void *ptr, size_t size, uint32_t bits);
shake128_ctx *shake128_new(uint32_t bits);
void shake128_delete(shake128_ctx *ctx);
void shake128_update(shake128_ctx *ctx, void *data, size_t size);
int32_t shake128_final(shake128_ctx *ctx, byte_t *buffer, size_t size);

shake128_ctx *shake256_init(void *ptr, size_t size, uint32_t bits);
shake256_ctx *shake256_new(uint32_t bits);
void shake256_delete(shake256_ctx *ctx);
void shake256_update(shake256_ctx *ctx, void *data, size_t size);
int32_t shake256_final(shake256_ctx *ctx, byte_t *buffer, size_t size);

#endif
