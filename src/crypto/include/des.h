/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DES_H
#define CRYPTO_DES_H

#include <stdbool.h>
#include <types.h>

#define DES_ROUNDS 16
#define DES_BLOCK_SIZE 8

typedef uint8_t des_round_key[6];

typedef struct _tdes_key
{
	des_round_key rk1[DES_ROUNDS], rk2[DES_ROUNDS], rk3[DES_ROUNDS];
} tdes_key;

tdes_key *new_tdes_key(byte_t k1[8], byte_t k2[8], byte_t k3[8], bool check);
void delete_tdes_key(tdes_key *key);

void tdes_encrypt_block(tdes_key *key, byte_t plaintext[DES_BLOCK_SIZE], byte_t ciphertext[DES_BLOCK_SIZE]);
void tdes_decrypt_block(tdes_key *key, byte_t ciphertext[DES_BLOCK_SIZE], byte_t plaintext[DES_BLOCK_SIZE]);

#endif
