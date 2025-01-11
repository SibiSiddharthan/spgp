/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include <types.h>

// See NIST FIPS-197 Advanced Encryption Standard (AES)

#define AES_MAX_ROUNDS 14
#define AES_BLOCK_SIZE 16

#define AES128_KEY_SIZE 16
#define AES192_KEY_SIZE 24
#define AES256_KEY_SIZE 32

typedef uint8_t aes_round_key[16];

typedef enum _aes_type
{
	AES128 = 1,
	AES192 = 2,
	AES256 = 3
} aes_type;

typedef struct _aes_key
{
	aes_type type;
	aes_round_key round_key[AES_MAX_ROUNDS + 1];
} aes_key;

aes_key *aes_key_init(void *ptr, size_t size, aes_type type, void *key, size_t key_size);
aes_key *aes_key_new(aes_type type, void *key, size_t key_size);
void aes_key_delete(aes_key *key);

void aes128_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE]);
void aes128_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE]);

void aes192_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE]);
void aes192_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE]);

void aes256_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE]);
void aes256_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE]);

void aes_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE]);
void aes_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE]);

#endif
