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

#define IDEA_ROUND(K, I, X1, X2, X3, X4)   \
	{                                      \
		uint16_t t1 = 0, t2 = 0;           \
                                           \
		X1 = IDEA_MUL(X1, K[(I * 6) + 0]); \
		X2 = X2 + K[(I * 6) + 1];          \
		X3 = X3 + K[(I * 6) + 2];          \
		X4 = IDEA_MUL(X4, K[(I * 6) + 3]); \
                                           \
		t1 = (X1 ^ X3);                    \
		t2 = (X2 ^ X4);                    \
		t1 = IDEA_MUL(t1, K[(I * 6) + 4]); \
		t2 = t1 + t2;                      \
		t2 = IDEA_MUL(t2, K[(I * 6) + 5]); \
		t1 = t1 + t2;                      \
                                           \
		X1 = X1 ^ t2;                      \
		X2 = X2 ^ t1;                      \
		X3 = X3 ^ t2;                      \
		X4 = X4 ^ t1;                      \
                                           \
		/* Swap X2,X3 */                   \
		X2 = X2 ^ X3;                      \
		X3 = X2 ^ X3;                      \
		X2 = X2 ^ X3;                      \
	}

static inline void load_idea_key(idea_key *expanded_key, uint32_t index, uint64_t k1, uint64_t k2)
{
	uint32_t offset = index * 8;

	expanded_key->ek[offset + 0] = (uint16_t)((k1 >> 48) & 0xFFFF);
	expanded_key->ek[offset + 1] = (uint16_t)((k1 >> 32) & 0xFFFF);
	expanded_key->ek[offset + 2] = (uint16_t)((k1 >> 16) & 0xFFFF);
	expanded_key->ek[offset + 3] = (uint16_t)((k1 >> 0) & 0xFFFF);

	expanded_key->ek[offset + 4] = (uint16_t)((k2 >> 48) & 0xFFFF);
	expanded_key->ek[offset + 5] = (uint16_t)((k2 >> 32) & 0xFFFF);
	expanded_key->ek[offset + 6] = (uint16_t)((k2 >> 16) & 0xFFFF);
	expanded_key->ek[offset + 7] = (uint16_t)((k2 >> 0) & 0xFFFF);
}

static inline uint16_t mul_inverse(uint16_t k)
{
	uint32_t n = 65537;
	uint32_t q = 0, r = 0;
	uint32_t u = 1, v = 0, t = 0;

	do
	{
		q = n / k;
		r = n % k;

		t = ((v + 65537) - ((u * q) % 65537)) % 65537;

		n = k;
		k = r;

		v = u;
		u = t;

	} while (r > 0);

	return v;
}

static inline uint16_t add_inverse(uint16_t k)
{
	return ~k + 1;
}

void idea_key_init(idea_key *expanded_key, byte_t key[IDEA_KEY_SIZE])
{
	uint64_t k1 = 0, k2 = 0, k3 = 0, k4 = 0;
	uint64_t *k = (uint64_t *)key;

	memset(expanded_key, 0, sizeof(idea_key));

	k1 = BSWAP_64(k[0]);
	k2 = BSWAP_64(k[1]);

	// Expand the encryption key
	// First 8 blocks of round keys are just the key itself
	load_idea_key(expanded_key, 0, k1, k2);

	for (uint32_t i = 1; i < 7; ++i)
	{
		k3 = (k1 << 25 | k2 >> 39);
		k4 = (k2 << 25 | k1 >> 39);

		k1 = k3;
		k2 = k4;

		load_idea_key(expanded_key, i, k1, k2);
	}

	// Expand the decryption key
	expanded_key->dk[0] = mul_inverse(expanded_key->ek[48]);
	expanded_key->dk[1] = add_inverse(expanded_key->ek[49]);
	expanded_key->dk[2] = add_inverse(expanded_key->ek[50]);
	expanded_key->dk[3] = mul_inverse(expanded_key->ek[51]);
	expanded_key->dk[4] = expanded_key->ek[46];
	expanded_key->dk[5] = expanded_key->ek[47];

	for (uint32_t i = 6; i < 48; i += 6)
	{
		expanded_key->dk[i + 0] = mul_inverse(expanded_key->ek[48 - i]);
		expanded_key->dk[i + 1] = add_inverse(expanded_key->ek[50 - i]);
		expanded_key->dk[i + 2] = add_inverse(expanded_key->ek[49 - i]);
		expanded_key->dk[i + 3] = mul_inverse(expanded_key->ek[51 - i]);
		expanded_key->dk[i + 4] = expanded_key->ek[46 - i];
		expanded_key->dk[i + 5] = expanded_key->ek[47 - i];
	}

	expanded_key->dk[48] = mul_inverse(expanded_key->ek[0]);
	expanded_key->dk[49] = add_inverse(expanded_key->ek[1]);
	expanded_key->dk[50] = add_inverse(expanded_key->ek[2]);
	expanded_key->dk[51] = mul_inverse(expanded_key->ek[3]);
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
	IDEA_ROUND(key->ek, 0, x1, x2, x3, x4);
	IDEA_ROUND(key->ek, 1, x1, x2, x3, x4);
	IDEA_ROUND(key->ek, 2, x1, x2, x3, x4);
	IDEA_ROUND(key->ek, 3, x1, x2, x3, x4);
	IDEA_ROUND(key->ek, 4, x1, x2, x3, x4);
	IDEA_ROUND(key->ek, 5, x1, x2, x3, x4);
	IDEA_ROUND(key->ek, 6, x1, x2, x3, x4);
	IDEA_ROUND(key->ek, 7, x1, x2, x3, x4);

	x1 = IDEA_MUL(x1, key->ek[48]);
	x2 = x2 + key->ek[50];
	x3 = x3 + key->ek[49];
	x4 = IDEA_MUL(x4, key->ek[51]);

	c[0] = BSWAP_16(x1);
	c[1] = BSWAP_16(x3);
	c[2] = BSWAP_16(x2);
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

	// 8 rounds
	IDEA_ROUND(key->dk, 0, x1, x2, x3, x4);
	IDEA_ROUND(key->dk, 1, x1, x2, x3, x4);
	IDEA_ROUND(key->dk, 2, x1, x2, x3, x4);
	IDEA_ROUND(key->dk, 3, x1, x2, x3, x4);
	IDEA_ROUND(key->dk, 4, x1, x2, x3, x4);
	IDEA_ROUND(key->dk, 5, x1, x2, x3, x4);
	IDEA_ROUND(key->dk, 6, x1, x2, x3, x4);
	IDEA_ROUND(key->dk, 7, x1, x2, x3, x4);

	x1 = IDEA_MUL(x1, key->dk[48]);
	x2 = x2 + key->dk[50];
	x3 = x3 + key->dk[49];
	x4 = IDEA_MUL(x4, key->dk[51]);

	p[0] = BSWAP_16(x1);
	p[1] = BSWAP_16(x3);
	p[2] = BSWAP_16(x2);
	p[3] = BSWAP_16(x4);
}
