/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_TWOFISH_H
#define CRYPTO_TWOFISH_H

#include <types.h>

// See Twofish: A 128-Bit Block Cipher

#define TWOFISH_ROUNDS     16
#define TWOFISH_BLOCK_SIZE 16
#define TWOFISH_ROUND_KEYS ((TWOFISH_BLOCK_SIZE * 2) + 4 + 4)

#define TWOFISH128_KEY_SIZE 16
#define TWOFISH192_KEY_SIZE 24
#define TWOFISH256_KEY_SIZE 32

typedef uint32_t twofish_round_key;

typedef enum _twofish_type
{
	TWOFISH128,
	TWOFISH192,
	TWOFISH256
} twofish_type;

typedef struct _twofish_key
{
	twofish_type type;
	twofish_round_key round_key[TWOFISH_ROUND_KEYS];
	byte_t sbox0[256], sbox1[256], sbox2[256], sbox3[256];
} twofish_key;

twofish_key *twofish_key_init(void *ptr, size_t size, twofish_type type, void *key, size_t key_size);
twofish_key *twofish_key_new(twofish_type type, void *key, size_t key_size);
void twofish_key_delete(twofish_key *key);

void twofish_encrypt_block(twofish_key *key, byte_t plaintext[TWOFISH_BLOCK_SIZE], byte_t ciphertext[TWOFISH_BLOCK_SIZE]);
void twofish_decrypt_block(twofish_key *key, byte_t ciphertext[TWOFISH_BLOCK_SIZE], byte_t plaintext[TWOFISH_BLOCK_SIZE]);

#endif
