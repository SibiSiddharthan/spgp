/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CAST5_H
#define CRYPTO_CAST5_H

#include <crypt.h>

// See NIST FIPS-197 Advanced Encryption Standard (CAST5)

#define CAST5_MAX_ROUNDS 16
#define CAST5_BLOCK_SIZE 8

#define CAST5_KEY_SIZE 16

typedef struct _cast5_key
{
	uint32_t km[CAST5_MAX_ROUNDS], kr[CAST5_MAX_ROUNDS];
} cast5_key;

void cast5_key_init(cast5_key *expanded_key, byte_t key[CAST5_KEY_SIZE]);

void cast5_encrypt_block(cast5_key *key, byte_t plaintext[CAST5_BLOCK_SIZE], byte_t ciphertext[CAST5_BLOCK_SIZE]);
void cast5_decrypt_block(cast5_key *key, byte_t ciphertext[CAST5_BLOCK_SIZE], byte_t plaintext[CAST5_BLOCK_SIZE]);

#endif
