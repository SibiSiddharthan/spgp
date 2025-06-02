/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_IDEA_H
#define CRYPTO_IDEA_H

#include <crypt.h>

// See NIST FIPS-197 Advanced Encryption Standard (IDEA)

#define IDEA_MAX_ROUNDS 8
#define IDEA_BLOCK_SIZE 8

#define IDEA_KEY_SIZE 16

typedef struct _idea_key
{
	uint16_t k[56];
} idea_key;

void idea_key_init(idea_key *expanded_key, byte_t key[IDEA_KEY_SIZE]);

void idea_encrypt_block(idea_key *key, byte_t plaintext[IDEA_BLOCK_SIZE], byte_t ciphertext[IDEA_BLOCK_SIZE]);
void idea_decrypt_block(idea_key *key, byte_t ciphertext[IDEA_BLOCK_SIZE], byte_t plaintext[IDEA_BLOCK_SIZE]);

#endif
