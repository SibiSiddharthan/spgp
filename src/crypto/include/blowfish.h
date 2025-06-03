/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BLOWFISH_H
#define CRYPTO_BLOWFISH_H

#include <crypt.h>

// See NIST FIPS-197 Advanced Encryption Standard (BLOWFISH)

#define BLOWFISH_MAX_ROUNDS 16
#define BLOWFISH_BLOCK_SIZE 8

#define BLOWFISH64_KEY_SIZE  8
#define BLOWFISH128_KEY_SIZE 16

typedef struct _blowfish_key
{
	uint32_t round_key[BLOWFISH_MAX_ROUNDS + 2];
	uint32_t sbox0[256], sbox1[256], sbox2[256], sbox3[256];
} blowfish_key;

void blowfish64_key_init(blowfish_key *expanded_key, byte_t key[BLOWFISH64_KEY_SIZE]);
void blowfish128_key_init(blowfish_key *expanded_key, byte_t key[BLOWFISH128_KEY_SIZE]);

void blowfish_encrypt_block(blowfish_key *key, byte_t plaintext[BLOWFISH_BLOCK_SIZE], byte_t ciphertext[BLOWFISH_BLOCK_SIZE]);
void blowfish_decrypt_block(blowfish_key *key, byte_t ciphertext[BLOWFISH_BLOCK_SIZE], byte_t plaintext[BLOWFISH_BLOCK_SIZE]);

#endif
