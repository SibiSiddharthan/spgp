/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_MD5_H
#define CRYPTO_MD5_H

#include <types.h>

// See RFC 1321 : The MD5 Message-Digest Algorithm

#define MD5_HASH_SIZE  16
#define MD5_BLOCK_SIZE 64

typedef struct _md5_ctx
{
	uint32_t a, b, c, d;
	uint64_t size;
	byte_t internal[MD5_BLOCK_SIZE];
} md5_ctx;

md5_ctx *md5_init(void *ptr, size_t size);
md5_ctx *md5_new(void);
void md5_delete(md5_ctx *ctx);
void md5_reset(md5_ctx *ctx);
void md5_update(md5_ctx *ctx, void *data, size_t size);
void md5_final(md5_ctx *ctx, byte_t buffer[MD5_HASH_SIZE]);
void md5_hash(void *data, size_t size, byte_t buffer[MD5_HASH_SIZE]);

#endif
