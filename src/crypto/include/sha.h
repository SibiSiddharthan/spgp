/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_SHA_H
#define CRYPTO_SHA_H

#include <types.h>

#define SHA1_HASH_SIZE  20
#define SHA1_BLOCK_SIZE 64

#define SHA224_HASH_SIZE  28
#define SHA256_HASH_SIZE  32
#define SHA256_BLOCK_SIZE 64

#define SHA384_HASH_SIZE     48
#define SHA512_HASH_SIZE     64
#define SHA512_224_HASH_SIZE 28
#define SHA512_256_HASH_SIZE 32
#define SHA512_BLOCK_SIZE    128

typedef struct _sha1_ctx
{
	uint32_t h0, h1, h2, h3, h4;
	uint64_t size;
	byte_t internal[SHA1_BLOCK_SIZE];
} sha1_ctx;

typedef struct _sha256_ctx
{
	uint32_t h0, h1, h2, h3, h4, h5, h6, h7;
	uint64_t size;
	byte_t internal[SHA256_BLOCK_SIZE];
} sha224_ctx, sha256_ctx;

sha1_ctx *sha1_init(void);
void sha1_free(sha1_ctx *ctx);
void sha1_reset(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, void *data, size_t size);
void sha1_final(sha1_ctx *ctx, byte_t buffer[SHA1_HASH_SIZE]);
int32_t sha1_quick_hash(void *data, size_t size, byte_t buffer[SHA1_HASH_SIZE]);

sha224_ctx *sha224_init(void);
void sha224_free(sha224_ctx *ctx);
void sha224_reset(sha224_ctx *ctx);
void sha224_update(sha224_ctx *ctx, void *data, size_t size);
void sha224_final(sha224_ctx *ctx, byte_t buffer[SHA224_HASH_SIZE]);
int32_t sha224_quick_hash(void *data, size_t size, byte_t buffer[SHA224_HASH_SIZE]);

sha256_ctx *sha256_init(void);
void sha256_free(sha256_ctx *ctx);
void sha256_reset(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, void *data, size_t size);
void sha256_final(sha256_ctx *ctx, byte_t buffer[SHA256_HASH_SIZE]);
int32_t sha256_quick_hash(void *data, size_t size, byte_t buffer[SHA256_HASH_SIZE]);

#endif
