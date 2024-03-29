/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_MD5_H
#define CRYPTO_MD5_H

#include <types.h>

#define MD5_HASH_SIZE  16
#define MD5_BLOCK_SIZE 64

typedef struct _md5_ctx
{
	uint32_t a, b, c, d;
	uint64_t size;
	byte_t internal[MD5_BLOCK_SIZE];
} md5_ctx;

md5_ctx *md5_init(void);
void md5_free(md5_ctx *ctx);
void md5_reset(md5_ctx *ctx);
void md5_update(md5_ctx *ctx, void *data, size_t size);
void md5_final(md5_ctx *ctx, byte_t buffer[MD5_HASH_SIZE]);
int32_t md5_hash(void *data, size_t size, byte_t buffer[MD5_HASH_SIZE]);

#endif
