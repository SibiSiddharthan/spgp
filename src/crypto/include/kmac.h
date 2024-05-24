/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_KMAC_H
#define CRYPTO_KMAC_H

#include <shake.h>

#define KMAC128_BLOCK_SIZE SHAKE128_BLOCK_SIZE
#define KMAC256_BLOCK_SIZE SHAKE256_BLOCK_SIZE

typedef sha3_ctx kmac128_ctx;
typedef sha3_ctx kmac256_ctx;

kmac128_ctx *kmac128_init(void *ptr, size_t size, uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size);
kmac128_ctx *kmac128_new(uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size);
void kmac128_delete(kmac128_ctx *ctx);
void kmac128_update(kmac128_ctx *ctx, void *data, size_t size);
void kmac128_final(kmac128_ctx *ctx, byte_t *buffer, size_t size);

kmac256_ctx *kmac256_init(void *ptr, size_t size, uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size);
kmac256_ctx *kmac256_new(uint32_t bits, byte_t *key, size_t key_size, byte_t *custom, size_t custom_size);
void kmac256_delete(kmac256_ctx *ctx);
void kmac256_update(kmac256_ctx *ctx, void *data, size_t size);
void kmac256_final(kmac256_ctx *ctx, byte_t *buffer, size_t size);

#endif
