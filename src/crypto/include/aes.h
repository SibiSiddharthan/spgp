/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include <crypt.h>

// See NIST FIPS-197 Advanced Encryption Standard (AES)

#define AES_MAX_ROUNDS 14
#define AES_BLOCK_SIZE 16

#define AES128_KEY_SIZE 16
#define AES192_KEY_SIZE 24
#define AES256_KEY_SIZE 32

typedef uint8_t aes_round_key[16];

typedef struct _aes_key
{
	aes_round_key round_key[AES_MAX_ROUNDS + 1];
} aes_key;

void aes128_key_init(aes_key *expanded_key, byte_t key[AES128_KEY_SIZE]);
void aes192_key_init(aes_key *expanded_key, byte_t key[AES192_KEY_SIZE]);
void aes256_key_init(aes_key *expanded_key, byte_t key[AES256_KEY_SIZE]);

void aes128_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE]);
void aes128_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE]);

void aes192_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE]);
void aes192_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE]);

void aes256_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE]);
void aes256_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE]);

#endif
