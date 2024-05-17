/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DES_H
#define CRYPTO_DES_H

#include <stdbool.h>
#include <types.h>

#define DES_ROUNDS     16
#define DES_BLOCK_SIZE 8
#define DES_KEY_SIZE   8

typedef uint8_t des_round_key[6];

typedef struct _tdes_key
{
	des_round_key rk1[DES_ROUNDS], rk2[DES_ROUNDS], rk3[DES_ROUNDS];
} tdes_key;

tdes_key *tdes_key_init(void *ptr, size_t size, byte_t k1[DES_KEY_SIZE], byte_t k2[DES_KEY_SIZE], byte_t k3[DES_KEY_SIZE], bool check);
tdes_key *tdes_key_new(byte_t k1[DES_KEY_SIZE], byte_t k2[DES_KEY_SIZE], byte_t k3[DES_KEY_SIZE], bool check);
void tdes_key_delete(tdes_key *key);

void tdes_encrypt_block(tdes_key *key, byte_t plaintext[DES_BLOCK_SIZE], byte_t ciphertext[DES_BLOCK_SIZE]);
void tdes_decrypt_block(tdes_key *key, byte_t ciphertext[DES_BLOCK_SIZE], byte_t plaintext[DES_BLOCK_SIZE]);

#endif
