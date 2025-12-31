/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_TWOFISH_H
#define CRYPTO_TWOFISH_H

#include <crypt.h>

// See Twofish: A 128-Bit Block Cipher

#define TWOFISH_ROUNDS     16
#define TWOFISH_BLOCK_SIZE 16
#define TWOFISH_ROUND_KEYS ((TWOFISH_BLOCK_SIZE * 2) + 4 + 4)

#define TWOFISH128_KEY_SIZE 16
#define TWOFISH192_KEY_SIZE 24
#define TWOFISH256_KEY_SIZE 32

typedef uint32_t twofish_round_key;

typedef struct _twofish_key
{
	twofish_round_key round_key[TWOFISH_ROUND_KEYS];
	byte_t sbox0[256], sbox1[256], sbox2[256], sbox3[256];
} twofish_key;

void twofish128_key_init(twofish_key *expanded_key, byte_t key[TWOFISH128_KEY_SIZE]);
void twofish192_key_init(twofish_key *expanded_key, byte_t key[TWOFISH192_KEY_SIZE]);
void twofish256_key_init(twofish_key *expanded_key, byte_t key[TWOFISH256_KEY_SIZE]);

void twofish_encrypt_block(twofish_key *key, byte_t plaintext[TWOFISH_BLOCK_SIZE], byte_t ciphertext[TWOFISH_BLOCK_SIZE]);
void twofish_decrypt_block(twofish_key *key, byte_t ciphertext[TWOFISH_BLOCK_SIZE], byte_t plaintext[TWOFISH_BLOCK_SIZE]);

#endif
