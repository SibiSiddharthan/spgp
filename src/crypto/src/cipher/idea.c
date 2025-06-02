/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <idea.h>
#include <byteswap.h>
#include <string.h>

#define IDEA_ZERO(X)   ((uint32_t)((X) == 0 ? 65536 : (X)))
#define IDEA_MUL(X, Y) ((uint16_t)((IDEA_ZERO(X) * IDEA_ZERO(Y)) % 65537))

#define IDEA_ROUND(K, I, X1, X2, X3, X4)      \
	{                                         \
		uint16_t t1 = 0, t2 = 0;              \
                                              \
		X1 = IDEA_MUL(X1, K->k[(I * 6) + 0]); \
		X2 = X2 + K->k[(I * 6) + 1];          \
		X3 = X3 + K->k[(I * 6) + 2];          \
		X4 = IDEA_MUL(X4, K->k[(I * 6) + 3]); \
                                              \
		t1 = (X1 ^ X3);                       \
		t2 = (X2 ^ X4);                       \
		t1 = IDEA_MUL(t1, K->k[(I * 6) + 4]); \
		t2 = t1 + t2;                         \
		t2 = IDEA_MUL(t2, K->k[(I * 6) + 5]); \
		t1 = t1 + t2;                         \
                                              \
		X1 = X1 ^ t2;                         \
		X2 = X2 ^ t1;                         \
		X3 = X3 ^ t2;                         \
		X4 = X4 ^ t1;                         \
                                              \
		/* Swap X2,X3 */                      \
		X2 = X2 ^ X3;                         \
		X3 = X2 ^ X3;                         \
		X2 = X2 ^ X3;                         \
	}

void idea_key_init(idea_key *expanded_key, byte_t key[IDEA_KEY_SIZE])
{
	uint64_t k1 = 0, k2 = 0, k3 = 0, k4 = 0;
	uint64_t *k = (uint64_t *)key;

	// First 8 blocks of round keys are just the key itself
	memcpy(expanded_key->k, key, IDEA_KEY_SIZE);

	k1 = BSWAP_64(k[0]);
	k2 = BSWAP_64(k[1]);

	for (uint32_t i = 1; i < 8; ++i)
	{
		k3 = (k1 << 25 | k2 >> 39);
		k4 = (k2 << 25 | k1 >> 39);

		k1 = k3;
		k2 = k4;

		k3 = BSWAP_64(k3);
		k4 = BSWAP_64(k4);

		memcpy(&expanded_key->k[i * 8], &k3, 8);
		memcpy(&expanded_key->k[(i * 8) + 4], &k4, 8);

		// NOTE: The k4 copy during the last iteration will not be used.
	}
}

void idea_encrypt_block(idea_key *key, byte_t plaintext[IDEA_BLOCK_SIZE], byte_t ciphertext[IDEA_BLOCK_SIZE])
{
	uint16_t x1 = 0, x2 = 0, x3 = 0, x4 = 0;
	uint16_t *p = (uint16_t *)plaintext;
	uint16_t *c = (uint16_t *)ciphertext;

	x1 = BSWAP_16(p[0]);
	x2 = BSWAP_16(p[1]);
	x3 = BSWAP_16(p[2]);
	x4 = BSWAP_16(p[3]);

	// 8 rounds
	IDEA_ROUND(key, 0, x1, x2, x3, x4);
	IDEA_ROUND(key, 1, x1, x2, x3, x4);
	IDEA_ROUND(key, 2, x1, x2, x3, x4);
	IDEA_ROUND(key, 3, x1, x2, x3, x4);
	IDEA_ROUND(key, 4, x1, x2, x3, x4);
	IDEA_ROUND(key, 5, x1, x2, x3, x4);
	IDEA_ROUND(key, 6, x1, x2, x3, x4);
	IDEA_ROUND(key, 7, x1, x2, x3, x4);

	x1 = IDEA_MUL(x1, key->k[48]);
	x2 = x2 + key->k[49];
	x3 = x3 + key->k[50];
	x4 = IDEA_MUL(x4, key->k[51]);

	c[0] = BSWAP_16(x1);
	c[1] = BSWAP_16(x2);
	c[2] = BSWAP_16(x3);
	c[3] = BSWAP_16(x4);
}

void idea_decrypt_block(idea_key *key, byte_t ciphertext[IDEA_BLOCK_SIZE], byte_t plaintext[IDEA_BLOCK_SIZE])
{
	uint16_t x1 = 0, x2 = 0, x3 = 0, x4 = 0;
	uint16_t *p = (uint16_t *)plaintext;
	uint16_t *c = (uint16_t *)ciphertext;

	x1 = BSWAP_16(c[0]);
	x2 = BSWAP_16(c[1]);
	x3 = BSWAP_16(c[2]);
	x4 = BSWAP_16(c[3]);

	x1 = IDEA_MUL(x1, key->k[48]);
	x2 = x2 + key->k[49];
	x3 = x3 + key->k[50];
	x4 = IDEA_MUL(x4, key->k[51]);

	// 8 rounds
	IDEA_ROUND(key, 7, x1, x2, x3, x4);
	IDEA_ROUND(key, 6, x1, x2, x3, x4);
	IDEA_ROUND(key, 5, x1, x2, x3, x4);
	IDEA_ROUND(key, 4, x1, x2, x3, x4);
	IDEA_ROUND(key, 3, x1, x2, x3, x4);
	IDEA_ROUND(key, 2, x1, x2, x3, x4);
	IDEA_ROUND(key, 1, x1, x2, x3, x4);
	IDEA_ROUND(key, 0, x1, x2, x3, x4);

	p[0] = BSWAP_16(x1);
	p[1] = BSWAP_16(x2);
	p[2] = BSWAP_16(x3);
	p[3] = BSWAP_16(x4);
}
