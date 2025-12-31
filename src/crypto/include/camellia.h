/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CAMELLIA_H
#define CRYPTO_CAMELLIA_H

#include <crypt.h>

// See RFC 3713: A Description of the Camellia Encryption Algorithm

#define CAMELLIA_BLOCK_SIZE 16

#define CAMELLIA128_KEY_SIZE 16
#define CAMELLIA192_KEY_SIZE 24
#define CAMELLIA256_KEY_SIZE 32

typedef struct _camellia_key
{
	uint64_t k[24], ke[6], kw[4];
} camellia_key;

void camellia128_key_init(camellia_key *expanded_key, byte_t key[CAMELLIA128_KEY_SIZE]);
void camellia192_key_init(camellia_key *expanded_key, byte_t key[CAMELLIA192_KEY_SIZE]);
void camellia256_key_init(camellia_key *expanded_key, byte_t key[CAMELLIA256_KEY_SIZE]);

void camellia128_encrypt_block(camellia_key *key, byte_t plaintext[CAMELLIA_BLOCK_SIZE], byte_t ciphertext[CAMELLIA_BLOCK_SIZE]);
void camellia128_decrypt_block(camellia_key *key, byte_t ciphertext[CAMELLIA_BLOCK_SIZE], byte_t plaintext[CAMELLIA_BLOCK_SIZE]);

void camellia192_encrypt_block(camellia_key *key, byte_t plaintext[CAMELLIA_BLOCK_SIZE], byte_t ciphertext[CAMELLIA_BLOCK_SIZE]);
void camellia192_decrypt_block(camellia_key *key, byte_t ciphertext[CAMELLIA_BLOCK_SIZE], byte_t plaintext[CAMELLIA_BLOCK_SIZE]);

void camellia256_encrypt_block(camellia_key *key, byte_t plaintext[CAMELLIA_BLOCK_SIZE], byte_t ciphertext[CAMELLIA_BLOCK_SIZE]);
void camellia256_decrypt_block(camellia_key *key, byte_t ciphertext[CAMELLIA_BLOCK_SIZE], byte_t plaintext[CAMELLIA_BLOCK_SIZE]);

#endif
