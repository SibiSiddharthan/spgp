/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_HASH_ALGORITHM_H
#define CRYPTO_HASH_ALGORITHM_H

typedef enum _hash_algorithm
{
	HASH_MD5 = 1,
	HASH_RIPEMD160,
	HASH_BLAKE2B,
	HASH_BLAKE2S,
	HASH_SHA1,
	HASH_SHA224,
	HASH_SHA256,
	HASH_SHA384,
	HASH_SHA512,
	HASH_SHA512_224,
	HASH_SHA512_256,
	HASH_SHA3_224,
	HASH_SHA3_256,
	HASH_SHA3_384,
	HASH_SHA3_512
} hash_algorithm;

#define MAX_HASH_SIZE  64
#define MAX_BLOCK_SIZE 256

#endif
