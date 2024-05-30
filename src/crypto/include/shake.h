/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_SHAKE_H
#define CRYPTO_SHAKE_H

#include <sha.h>

// See NIST FIPS 202 : SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
// See NIST SP 800-185: SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash

#define SHAKE128_BLOCK_SIZE 168
#define SHAKE256_BLOCK_SIZE 136

typedef sha3_ctx shake128_ctx, shake256_ctx;

shake128_ctx *shake128_init(void *ptr, size_t size, uint32_t bits);
shake128_ctx *shake128_new(uint32_t bits);
void shake128_delete(shake128_ctx *ctx);
void shake128_reset(shake128_ctx *ctx, uint32_t bits);
void shake128_update(shake128_ctx *ctx, void *data, size_t size);
void shake128_final(shake128_ctx *ctx, void *buffer, size_t size);
void shake128_xof(void *data, size_t data_size, void *xof, size_t xof_size);

shake256_ctx *shake256_init(void *ptr, size_t size, uint32_t bits);
shake256_ctx *shake256_new(uint32_t bits);
void shake256_delete(shake256_ctx *ctx);
void shake256_reset(shake256_ctx *ctx, uint32_t bits);
void shake256_update(shake256_ctx *ctx, void *data, size_t size);
void shake256_final(shake256_ctx *ctx, void *buffer, size_t size);
void shake256_xof(void *data, size_t data_size, void *xof, size_t xof_size);

shake128_ctx *cshake128_init(void *ptr, size_t size, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size);
shake128_ctx *cshake128_new(uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size);
void cshake128_delete(shake128_ctx *ctx);
void cshake128_reset(shake128_ctx *ctx, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size);
void cshake128_update(shake128_ctx *ctx, void *data, size_t size);
void cshake128_final(shake128_ctx *ctx, void *buffer, size_t size);

shake256_ctx *cshake256_init(void *ptr, size_t size, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size);
shake256_ctx *cshake256_new(uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size);
void cshake256_delete(shake256_ctx *ctx);
void cshake256_reset(shake256_ctx *ctx, uint32_t bits, void *name, size_t name_size, void *custom, size_t custom_size);
void cshake256_update(shake256_ctx *ctx, void *data, size_t size);
void cshake256_final(shake256_ctx *ctx, void *buffer, size_t size);

#endif
