/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_ARIA_H
#define CRYPTO_ARIA_H

#include <types.h>

// See RFC 5794: A Description of the ARIA Encryption Algorithm

#define ARIA_MAX_ROUNDS 16
#define ARIA_BLOCK_SIZE 16

#define ARIA128_KEY_SIZE 16
#define ARIA192_KEY_SIZE 24
#define ARIA256_KEY_SIZE 32

typedef uint8_t aria_round_key[16];

typedef enum _aria_type
{
	ARIA128,
	ARIA192,
	ARIA256
} aria_type;

typedef struct _aria_key
{
	aria_type type;
	byte_t ck1[16], ck2[16], ck3[16];
	aria_round_key encryption_round_key[ARIA_MAX_ROUNDS + 1];
	aria_round_key decryption_round_key[ARIA_MAX_ROUNDS + 1];
} aria_key;

aria_key *aria_key_init(void *ptr, size_t size, aria_type type, void *key, size_t key_size);
aria_key *aria_key_new(aria_type type, void *key, size_t key_size);
void aria_key_delete(aria_key *key);

void aria128_encrypt_block(aria_key *key, byte_t plaintext[ARIA_BLOCK_SIZE], byte_t ciphertext[ARIA_BLOCK_SIZE]);
void aria128_decrypt_block(aria_key *key, byte_t ciphertext[ARIA_BLOCK_SIZE], byte_t plaintext[ARIA_BLOCK_SIZE]);

void aria192_encrypt_block(aria_key *key, byte_t plaintext[ARIA_BLOCK_SIZE], byte_t ciphertext[ARIA_BLOCK_SIZE]);
void aria192_decrypt_block(aria_key *key, byte_t ciphertext[ARIA_BLOCK_SIZE], byte_t plaintext[ARIA_BLOCK_SIZE]);

void aria256_encrypt_block(aria_key *key, byte_t plaintext[ARIA_BLOCK_SIZE], byte_t ciphertext[ARIA_BLOCK_SIZE]);
void aria256_decrypt_block(aria_key *key, byte_t ciphertext[ARIA_BLOCK_SIZE], byte_t plaintext[ARIA_BLOCK_SIZE]);

void aria_encrypt_block(aria_key *key, byte_t plaintext[ARIA_BLOCK_SIZE], byte_t ciphertext[ARIA_BLOCK_SIZE]);
void aria_decrypt_block(aria_key *key, byte_t ciphertext[ARIA_BLOCK_SIZE], byte_t plaintext[ARIA_BLOCK_SIZE]);

#endif
