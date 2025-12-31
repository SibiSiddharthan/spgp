/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DES_H
#define CRYPTO_DES_H

#include <crypt.h>

// See NIST FIPS 46-3 Data Encryption Standard (DES)

#define DES_ROUNDS     16
#define DES_BLOCK_SIZE 8
#define DES_KEY_SIZE   8

typedef uint8_t des_round_key[6];

typedef struct _tdes_key
{
	des_round_key rk1[DES_ROUNDS], rk2[DES_ROUNDS], rk3[DES_ROUNDS];
} tdes_key;

void tdes_key_init(tdes_key *key, byte_t k1[DES_KEY_SIZE], byte_t k2[DES_KEY_SIZE], byte_t k3[DES_KEY_SIZE]);
byte_t tdes_key_check(byte_t k1[DES_KEY_SIZE], byte_t k2[DES_KEY_SIZE], byte_t k3[DES_KEY_SIZE]);
uint32_t tdes_key_decode(void *key, byte_t key_size, byte_t k1[DES_KEY_SIZE], byte_t k2[DES_KEY_SIZE], byte_t k3[DES_KEY_SIZE]);

void tdes_encrypt_block(tdes_key *key, byte_t plaintext[DES_BLOCK_SIZE], byte_t ciphertext[DES_BLOCK_SIZE]);
void tdes_decrypt_block(tdes_key *key, byte_t ciphertext[DES_BLOCK_SIZE], byte_t plaintext[DES_BLOCK_SIZE]);

#endif
