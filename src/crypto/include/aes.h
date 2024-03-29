/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include <types.h>

#define AES_MAX_ROUNDS 14
#define AES_BLOCK_SIZE 16

typedef uint8_t aes_round_key[16];

typedef enum _aes_type
{
	AES128,
	AES192,
	AES256
} aes_type;

typedef struct _aes_key
{
	aes_round_key round_key[AES_MAX_ROUNDS + 1];
	aes_type type;
} aes_key;

aes_key *new_aes_key(aes_type type, byte_t *key);
void delete_aes_key(aes_key *key);

void aes_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE]);
void aes_decrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE]);

#endif
