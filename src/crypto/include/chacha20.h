/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CHACHA20_H
#define CRYPTO_CHACHA20_H

#include <crypt.h>

// See RFC 8439: ChaCha20 and Poly1305 for IETF Protocols

#define CHACHA20_BLOCK_SIZE 64
#define CHACHA20_KEY_SIZE   32
#define CHACHA20_NONCE_SIZE 12

typedef struct _chacha20_key
{
	uint32_t constants[4];
	byte_t key[32];
	uint32_t count;
	byte_t nonce[12];
} chacha20_key;

void chacha20_key_init(chacha20_key *chacha_key, byte_t key[CHACHA20_KEY_SIZE], byte_t nonce[CHACHA20_NONCE_SIZE]);

void chacha20_encrypt(chacha20_key *key, void *plaintext, void *ciphertext, size_t size);
void chacha20_decrypt(chacha20_key *key, void *ciphertext, void *plaintext, size_t size);

#endif
