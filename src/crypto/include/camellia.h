/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CAMELLIA_H
#define CRYPTO_CAMELLIA_H

#include <types.h>

#define CAMELLIA_BLOCK_SIZE 16

typedef enum _camellia_type
{
	CAMELLIA128,
	CAMELLIA192,
	CAMELLIA256
} camellia_type;

typedef struct _camellia_key
{
	uint64_t k[24], ke[6], kw[4];
	camellia_type type;
} camellia_key;

camellia_key *new_camellia_key(camellia_type type, byte_t *key);
void delete_camellia_key(camellia_key *key);

void camellia_encrypt_block(camellia_key *key, byte_t plaintext[CAMELLIA_BLOCK_SIZE], byte_t ciphertext[CAMELLIA_BLOCK_SIZE]);
void camellia_decrypt_block(camellia_key *key, byte_t plaintext[CAMELLIA_BLOCK_SIZE], byte_t ciphertext[CAMELLIA_BLOCK_SIZE]);

#endif
