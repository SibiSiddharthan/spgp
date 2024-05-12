/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CAMELLIA_H
#define CRYPTO_CAMELLIA_H

#include <types.h>

#define CAMELLIA_BLOCK_SIZE 16

#define CAMELLIA128_KEY_SIZE 16
#define CAMELLIA192_KEY_SIZE 24
#define CAMELLIA256_KEY_SIZE 32

typedef enum _camellia_type
{
	CAMELLIA128,
	CAMELLIA192,
	CAMELLIA256
} camellia_type;

typedef struct _camellia_key
{
	camellia_type type;
	uint64_t k[24], ke[6], kw[4];
} camellia_key;

camellia_key *camellia_key_new(camellia_type type, byte_t *key, size_t size);
void camellia_key_delete(camellia_key *key);

void camellia_encrypt_block(camellia_key *key, byte_t plaintext[CAMELLIA_BLOCK_SIZE], byte_t ciphertext[CAMELLIA_BLOCK_SIZE]);
void camellia_decrypt_block(camellia_key *key, byte_t ciphertext[CAMELLIA_BLOCK_SIZE], byte_t plaintext[CAMELLIA_BLOCK_SIZE]);

#endif
