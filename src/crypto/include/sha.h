/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_SHA_H
#define CRYPTO_SHA_H

#include <types.h>

// See NIST FIPS 180-4 : Secure Hash Standard (SHS)
// See NIST FIPS 202 : SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions

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

#define SHA3_224_BLOCK_SIZE 144
#define SHA3_256_BLOCK_SIZE 136
#define SHA3_384_BLOCK_SIZE 104
#define SHA3_512_BLOCK_SIZE 72

#define SHA3_224_HASH_SIZE 28
#define SHA3_256_HASH_SIZE 32
#define SHA3_384_HASH_SIZE 48
#define SHA3_512_HASH_SIZE 64

#define KECCAK1600_BLOCK_SIZE 200

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

typedef struct _sha512_ctx
{
	uint64_t h0, h1, h2, h3, h4, h5, h6, h7;
	uint64_t size_high, size_low;
	byte_t internal[SHA512_BLOCK_SIZE];
} sha384_ctx, sha512_ctx, sha512_224_ctx, sha512_256_ctx;

typedef enum _sha3_type
{
	SHA3_224,
	SHA3_256,
	SHA3_384,
	SHA3_512
} sha3_type;

typedef struct _sha3_ctx
{
	uint32_t hash_size;
	uint32_t block_size;
	uint64_t message_size;
	byte_t block[KECCAK1600_BLOCK_SIZE];
	byte_t internal[KECCAK1600_BLOCK_SIZE];
} sha3_ctx, sha3_224_ctx, sha3_256_ctx, sha3_384_ctx, sha3_512_ctx;

// SHA-1

sha1_ctx *sha1_init(void *ptr, size_t size);
sha1_ctx *sha1_new(void);
void sha1_delete(sha1_ctx *ctx);
void sha1_reset(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, void *data, size_t size);
void sha1_final(sha1_ctx *ctx, byte_t buffer[SHA1_HASH_SIZE]);
void sha1_hash(void *data, size_t size, byte_t buffer[SHA1_HASH_SIZE]);

// SHA-2

sha224_ctx *sha224_init(void *ptr, size_t size);
sha224_ctx *sha224_new(void);
void sha224_delete(sha224_ctx *ctx);
void sha224_reset(sha224_ctx *ctx);
void sha224_update(sha224_ctx *ctx, void *data, size_t size);
void sha224_final(sha224_ctx *ctx, byte_t buffer[SHA224_HASH_SIZE]);
void sha224_hash(void *data, size_t size, byte_t buffer[SHA224_HASH_SIZE]);

sha256_ctx *sha256_init(void *ptr, size_t size);
sha256_ctx *sha256_new(void);
void sha256_delete(sha256_ctx *ctx);
void sha256_reset(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, void *data, size_t size);
void sha256_final(sha256_ctx *ctx, byte_t buffer[SHA256_HASH_SIZE]);
void sha256_hash(void *data, size_t size, byte_t buffer[SHA256_HASH_SIZE]);

sha384_ctx *sha384_init(void *ptr, size_t size);
sha384_ctx *sha384_new(void);
void sha384_delete(sha384_ctx *ctx);
void sha384_reset(sha384_ctx *ctx);
void sha384_update(sha384_ctx *ctx, void *data, size_t size);
void sha384_final(sha384_ctx *ctx, byte_t buffer[SHA384_HASH_SIZE]);
void sha384_hash(void *data, size_t size, byte_t buffer[SHA384_HASH_SIZE]);

sha512_ctx *sha512_init(void *ptr, size_t size);
sha512_ctx *sha512_new(void);
void sha512_delete(sha512_ctx *ctx);
void sha512_reset(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, void *data, size_t size);
void sha512_final(sha512_ctx *ctx, byte_t buffer[SHA512_HASH_SIZE]);
void sha512_hash(void *data, size_t size, byte_t buffer[SHA512_HASH_SIZE]);

sha512_224_ctx *sha512_224_init(void *ptr, size_t size);
sha512_224_ctx *sha512_224_new(void);
void sha512_224_delete(sha512_224_ctx *ctx);
void sha512_224_reset(sha512_224_ctx *ctx);
void sha512_224_update(sha512_224_ctx *ctx, void *data, size_t size);
void sha512_224_final(sha512_224_ctx *ctx, byte_t buffer[SHA512_224_HASH_SIZE]);
void sha512_224_hash(void *data, size_t size, byte_t buffer[SHA512_224_HASH_SIZE]);

sha512_256_ctx *sha512_256_init(void *ptr, size_t size);
sha512_256_ctx *sha512_256_new(void);
void sha512_256_delete(sha512_256_ctx *ctx);
void sha512_256_reset(sha512_256_ctx *ctx);
void sha512_256_update(sha512_256_ctx *ctx, void *data, size_t size);
void sha512_256_final(sha512_256_ctx *ctx, byte_t buffer[SHA512_256_HASH_SIZE]);
void sha512_256_hash(void *data, size_t size, byte_t buffer[SHA512_256_HASH_SIZE]);

// SHA-3

sha3_ctx *sha3_init(void *ptr, size_t size, sha3_type type);
sha3_ctx *sha3_new(sha3_type type);
void sha3_delete(sha3_ctx *ctx);
void sha3_reset(sha3_ctx *ctx);
void sha3_update(sha3_ctx *ctx, void *data, size_t size);
int32_t sha3_final(sha3_ctx *ctx, void *buffer, size_t size);

sha3_224_ctx *sha3_224_init(void *ptr, size_t size);
sha3_224_ctx *sha3_224_new(void);
void sha3_224_delete(sha3_224_ctx *ctx);
void sha3_224_reset(sha3_224_ctx *ctx);
void sha3_224_update(sha3_224_ctx *ctx, void *data, size_t size);
void sha3_224_final(sha3_224_ctx *ctx, byte_t buffer[SHA3_224_HASH_SIZE]);
void sha3_224_hash(void *data, size_t size, byte_t buffer[SHA3_224_HASH_SIZE]);

sha3_256_ctx *sha3_256_init(void *ptr, size_t size);
sha3_256_ctx *sha3_256_new(void);
void sha3_256_delete(sha3_256_ctx *ctx);
void sha3_256_reset(sha3_256_ctx *ctx);
void sha3_256_update(sha3_256_ctx *ctx, void *data, size_t size);
void sha3_256_final(sha3_256_ctx *ctx, byte_t buffer[SHA3_256_HASH_SIZE]);
void sha3_256_hash(void *data, size_t size, byte_t buffer[SHA3_256_HASH_SIZE]);

sha3_384_ctx *sha3_384_init(void *ptr, size_t size);
sha3_384_ctx *sha3_384_new(void);
void sha3_384_delete(sha3_384_ctx *ctx);
void sha3_384_reset(sha3_384_ctx *ctx);
void sha3_384_update(sha3_384_ctx *ctx, void *data, size_t size);
void sha3_384_final(sha3_384_ctx *ctx, byte_t buffer[SHA3_384_HASH_SIZE]);
void sha3_384_hash(void *data, size_t size, byte_t buffer[SHA3_384_HASH_SIZE]);

sha3_512_ctx *sha3_512_init(void *ptr, size_t size);
sha3_512_ctx *sha3_512_new(void);
void sha3_512_delete(sha3_512_ctx *ctx);
void sha3_512_reset(sha3_512_ctx *ctx);
void sha3_512_update(sha3_512_ctx *ctx, void *data, size_t size);
void sha3_512_final(sha3_512_ctx *ctx, byte_t buffer[SHA3_512_HASH_SIZE]);
void sha3_512_hash(void *data, size_t size, byte_t buffer[SHA3_512_HASH_SIZE]);

#endif
