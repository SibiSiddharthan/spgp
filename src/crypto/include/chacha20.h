/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CHACHA20_H
#define CRYPTO_CHACHA20_H

#include <types.h>

#define CHACHA20_BLOCK_SIZE  64
#define CHACHA20_KEY_SIZE    32
#define CHACHA20_NONCE_SIZE  24

typedef struct _chacha20_key
{
	uint32_t constants[4];
	byte_t key[32];
	uint32_t count;
	byte_t nonce[12];
} chacha20_key;

chacha20_key *chacha20_new_key(byte_t *key, byte_t *nonce);
void chacha20_delete_key(chacha20_key *key);

void chacha20_encrypt(chacha20_key *key, byte_t *plaintext, byte_t *ciphertext, size_t size);
void chacha20_decrypt(chacha20_key *key, byte_t *ciphertext, byte_t *plaintext, size_t size);

#endif
