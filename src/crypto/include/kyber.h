/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_KYBER_H
#define CRYPTO_KYBER_H

#include <sha.h>
#include <shake.h>

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_512_PUBLIC_KEY_SIZE  800
#define KYBER_512_PRIVATE_KEY_SIZE 1632
#define KYBER_512_CIPHERTEXT_SIZE  768

#define KYBER_768_PUBLIC_KEY_SIZE  1184
#define KYBER_768_PRIVATE_KEY_SIZE 2400
#define KYBER_768_CIPHERTEXT_SIZE  1088

#define KYBER_1024_PUBLIC_KEY_SIZE  1568
#define KYBER_1024_PRIVATE_KEY_SIZE 3168
#define KYBER_1024_CIPHERTEXT_SIZE  1568

#define KYBER_SHARED_SECRET_SIZE 32

typedef enum _kyber_type
{
	KYBER_512 = 1,
	KYBER_768 = 2,
	KYBER_1024 = 3
} kyber_type;

typedef struct _kyber_key
{
	kyber_type type;

	uint8_t k;
	uint8_t e1;
	uint8_t e2;
	uint8_t du;
	uint8_t dv;

	byte_t *ek;
	byte_t *dk;

	shake256_ctx *p;
	shake256_ctx *j;

	sha3_256_ctx *g;
	sha3_512_ctx *h;

	void *buffer;

} kyber_key;

kyber_key *kyber_key_generate(kyber_type type);
kyber_key *kyber_key_new(kyber_type type);
void kyber_key_delete(kyber_key *key);

static inline void *kyber_key_get_public(kyber_key *key)
{
	return key->ek;
}

static inline void *kyber_key_get_private(kyber_key *key)
{
	return key->dk;
}

kyber_key *kyber_key_set_public(kyber_key *key, void *ek);
kyber_key *kyber_key_set_private(kyber_key *key, void *dk);

uint32_t kyber_public_encrypt(kyber_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size);
uint32_t kyber_private_decrypt(kyber_key *key, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size);

#endif
