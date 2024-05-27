/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <des.h>
#include <byteswap.h>

// See NIST FIPS 46-3 Data Encryption Standard (DES)

// clang-format off
// Permutation data
static const uint8_t IP[64] =
{
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
	56, 48, 40, 32, 24, 16,  8, 0,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6
};

static const uint8_t IIP[64] =
{
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25,
	32, 0, 40,  8, 48, 16, 56, 24
};

static const uint8_t P[32] =
{
	15,  6, 19, 20,
	28, 11, 27, 16,
	 0, 14, 22, 25,
	 4, 17, 30,  9,
	 1,  7, 23, 13,
	31, 26,  2,  8,
	18, 12, 29,  5,
	21, 10,  3, 24
};

static const uint8_t PC1_C[28] =
{
	56, 48, 40, 32, 24, 16,  8,
	 0, 57, 49, 41, 33, 25, 17,
	 9,  1, 58, 50, 42, 34, 26,
	18, 10,  2, 59, 51, 43, 35
};

static const uint8_t PC1_D[28] =
{
	62, 54, 46, 38, 30, 22, 14,
	6,  61, 53, 45, 37, 29, 21,
	13,  5, 60, 52, 44, 36, 28,
	20, 12,  4, 27, 19, 11,  3
};

static const uint8_t PC2_CD[48] =
{
	13, 16, 10, 23,  0,  4,
	 2, 27, 14,  5, 20,  9,
	22, 18, 11,  3, 25,  7,
	15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54,
	29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52,
	45, 41, 49, 35, 28, 31
};

// Key schedule left shifts
static const uint8_t KS_LS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Seletion table
static const uint8_t E[48] =
{
	31,  0,  1,  2,  3,  4,
	 3,  4,  5,  6,  7,  8,
	 7,  8,  9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31,  0
};

// S-boxes
static const uint8_t S1[64] =
{
	14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6,  13
};

static const uint8_t S2[64] =
{
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
};

static const uint8_t S3[64] =
{
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
};

static const uint8_t S4[64] =
{
	7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
};

static const uint8_t S5[64] =
{
	 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
};

static const uint8_t S6[64] =
{
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
};

static const uint8_t S7[64] =
{
	 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
};

static const uint8_t S8[64] =
{
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};

// clang-format on

#define GET_BIT(x, p)    ((x[(p) / 8] >> (7 - ((p) % 8))) & 0x1)
#define SET_BIT(x, p, b) x[(p) / 8] |= ((b) << (7 - ((p) % 8)))

#define SI(x) (((((((x) >> 5) & 0x1) << 1) | ((x) & 0x1)) * 16) + (((x) >> 1) & 0xF))

static inline uint32_t ROTL1(uint32_t x)
{
	byte_t *p = (byte_t *)&x;
	byte_t l = p[0] >> 7;

	p[0] = (p[0] << 1) | (p[1] >> 7);
	p[1] = (p[1] << 1) | (p[2] >> 7);
	p[2] = (p[2] << 1) | (p[3] >> 7);
	p[3] = (p[3] << 1) | (l << 4);

	return x;
}

static inline uint32_t ROTL2(uint32_t x)
{
	byte_t *p = (byte_t *)&x;
	byte_t l = p[0] >> 6;

	p[0] = (p[0] << 2) | (p[1] >> 6);
	p[1] = (p[1] << 2) | (p[2] >> 6);
	p[2] = (p[2] << 2) | (p[3] >> 6);
	p[3] = (p[3] << 2) | (l << 4);

	return x;
}

// Permuted Choice - 1
static inline void PC1(byte_t k[DES_KEY_SIZE], uint32_t *c, uint32_t *d)
{
	byte_t *cp = (byte_t *)c;
	byte_t *dp = (byte_t *)d;

	*c = 0;
	*d = 0;

	for (uint8_t i = 0; i < 28; ++i)
	{
		SET_BIT(cp, i, GET_BIT(k, PC1_C[i]));
		SET_BIT(dp, i, GET_BIT(k, PC1_D[i]));
	}
}

// Permuted Choice - 2
static inline void PC2(des_round_key rk, uint32_t c, uint32_t d)
{
	byte_t k[8];

	k[0] = c & 0xFF;
	k[1] = (c >> 8) & 0xFF;
	k[2] = (c >> 16) & 0xFF;
	k[3] = ((c >> 24) & 0xF0) | ((d & 0xF0) >> 4);
	k[4] = ((d & 0x0F) << 4) | (((d >> 8) & 0xF0) >> 4);
	k[5] = (((d >> 8) & 0x0F) << 4) | (((d >> 16) & 0xF0) >> 4);
	k[6] = (((d >> 16) & 0x0F) << 4) | (((d >> 24) & 0xF0) >> 4);
	k[7] = 0; // padding

	for (uint8_t i = 0; i < 48; ++i)
	{
		SET_BIT(rk, i, GET_BIT(k, PC2_CD[i]));
	}
}

// Initial Permutation
static inline uint64_t PIP(uint64_t m)
{
	uint64_t r = 0;
	byte_t *mp = (byte_t *)&m;
	byte_t *rp = (byte_t *)&r;

	for (uint8_t i = 0; i < 64; ++i)
	{
		SET_BIT(rp, i, GET_BIT(mp, IP[i]));
	}

	return r;
}

// Inverse Permutation
static inline uint64_t PIIP(uint64_t m)
{
	uint64_t r = 0;
	byte_t *mp = (byte_t *)&m;
	byte_t *rp = (byte_t *)&r;

	for (uint8_t i = 0; i < 64; ++i)
	{
		SET_BIT(rp, i, GET_BIT(mp, IIP[i]));
	}

	return r;
}

// Selection permutation
static inline void SE(byte_t e[6], uint32_t r)
{
	byte_t *rp = (byte_t *)&r;

	for (uint8_t i = 0; i < 48; ++i)
	{
		SET_BIT(e, i, GET_BIT(rp, E[i]));
	}
}

// Round Permutation
static inline uint32_t PP(uint32_t r)
{
	uint32_t o = 0;
	byte_t *rp = (byte_t *)&r;
	byte_t *op = (byte_t *)&o;

	for (uint8_t i = 0; i < 48; ++i)
	{
		SET_BIT(op, i, GET_BIT(rp, P[i]));
	}

	return o;
}

static inline uint32_t F(uint32_t r, des_round_key k)
{
	byte_t e[6] = {0};
	uint32_t o = 0;

	SE(e, r);

	e[0] ^= k[0];
	e[1] ^= k[1];
	e[2] ^= k[2];
	e[3] ^= k[3];
	e[4] ^= k[4];
	e[5] ^= k[5];

	o |= (S1[SI((e[0] & 0xFC) >> 2)] << 4);
	o |= (S2[SI(((e[0] & 0x3) << 4) | (e[1] >> 4))]);
	o |= (S3[SI(((e[1] & 0xF) << 2) | (e[2] >> 6))] << 12);
	o |= (S4[SI(e[2] & 0x3F)] << 8);
	o |= (S5[SI((e[3] & 0xFC) >> 2)] << 20);
	o |= (S6[SI(((e[3] & 0x3) << 4) | (e[4] >> 4))] << 16);
	o |= (S7[SI(((e[4] & 0xF) << 2) | (e[5] >> 6))] << 28);
	o |= (S8[SI(e[5] & 0x3F)] << 24);

	o = PP(o);

	return o;
}

#define DES_STEP(I, L, R, K) \
	{                        \
		uint32_t _T = L;     \
		L = R;               \
		R = _T ^ F(R, K);    \
	}

static void des_encrypt_block(des_round_key key[DES_ROUNDS], byte_t plaintext[DES_BLOCK_SIZE], byte_t ciphertext[DES_BLOCK_SIZE])
{
	uint64_t t = *(uint64_t *)plaintext;
	uint32_t l, r;

	// Initial Permutation
	t = PIP(t);
	l = t & 0xFFFFFFFF;
	r = t >> 32;

	// Rounds 1 - 16
	DES_STEP(1, l, r, key[0]);
	DES_STEP(2, l, r, key[1]);
	DES_STEP(3, l, r, key[2]);
	DES_STEP(4, l, r, key[3]);
	DES_STEP(5, l, r, key[4]);
	DES_STEP(6, l, r, key[5]);
	DES_STEP(7, l, r, key[6]);
	DES_STEP(8, l, r, key[7]);
	DES_STEP(9, l, r, key[8]);
	DES_STEP(10, l, r, key[9]);
	DES_STEP(11, l, r, key[10]);
	DES_STEP(12, l, r, key[11]);
	DES_STEP(13, l, r, key[12]);
	DES_STEP(14, l, r, key[13]);
	DES_STEP(15, l, r, key[14]);
	DES_STEP(16, l, r, key[15]);

	// Final Permutation
	t = PIIP((uint64_t)r + ((uint64_t)l << 32));
	*(uint64_t *)ciphertext = t;
}

static void des_decrypt_block(des_round_key key[DES_ROUNDS], byte_t ciphertext[DES_BLOCK_SIZE], byte_t plaintext[DES_BLOCK_SIZE])
{
	uint64_t t = *(uint64_t *)ciphertext;
	uint32_t l, r;

	// Initial Permutation
	t = PIP(t);
	l = t & 0xFFFFFFFF;
	r = t >> 32;

	// Rounds 1 - 16
	DES_STEP(1, l, r, key[15]);
	DES_STEP(2, l, r, key[14]);
	DES_STEP(3, l, r, key[13]);
	DES_STEP(4, l, r, key[12]);
	DES_STEP(5, l, r, key[11]);
	DES_STEP(6, l, r, key[10]);
	DES_STEP(7, l, r, key[9]);
	DES_STEP(8, l, r, key[8]);
	DES_STEP(9, l, r, key[7]);
	DES_STEP(10, l, r, key[6]);
	DES_STEP(11, l, r, key[5]);
	DES_STEP(12, l, r, key[4]);
	DES_STEP(13, l, r, key[3]);
	DES_STEP(14, l, r, key[2]);
	DES_STEP(15, l, r, key[1]);
	DES_STEP(16, l, r, key[0]);

	// Final Permutation
	t = PIIP((uint64_t)r + ((uint64_t)l << 32));
	*(uint64_t *)plaintext = t;
}

static bool check_des_key(byte_t k[DES_KEY_SIZE])
{
	for (uint8_t i = 0; i < DES_KEY_SIZE; ++i)
	{
		uint8_t sum = 0;

		for (uint8_t j = 0; j < 7; ++j)
		{
			sum += (k[i] >> j) & 0x1;
		}

		// 8-bit is parity
		if ((sum & 0x1) != (k[i] >> 7))
		{
			return false;
		}
	}

	return true;
}

static void des_key_expansion(des_round_key rk[DES_ROUNDS], byte_t k[DES_KEY_SIZE])
{
	uint32_t c = 0, d = 0;

	// Initial permutation
	PC1(k, &c, &d);

	// Round 1 - 16
	for (uint8_t i = 0; i < DES_ROUNDS; ++i)
	{
		if (KS_LS[i] == 1)
		{
			c = ROTL1(c);
			d = ROTL1(d);
		}
		else
		{
			c = ROTL2(c);
			d = ROTL2(d);
		}
		PC2(rk[i], c, d);
	}
}

int32_t tdes_decode_key(void *key, size_t key_size, byte_t k1[DES_KEY_SIZE], byte_t k2[DES_KEY_SIZE], byte_t k3[DES_KEY_SIZE])
{
	switch (key_size)
	{
	case DES_KEY_SIZE:
		// 64(56) bit key. k1 = k2 = k3.
		memcpy(k1, key, DES_KEY_SIZE);
		memcpy(k2, key, DES_KEY_SIZE);
		memcpy(k3, key, DES_KEY_SIZE);
		break;
	case DES_KEY_SIZE * 2:
		// 128(112) bit key. k1 = k3.
		memcpy(k1, key, DES_KEY_SIZE);
		memcpy(k2, key + DES_KEY_SIZE, DES_KEY_SIZE);
		memcpy(k3, key, DES_KEY_SIZE);
		break;
	case DES_KEY_SIZE * 3:
		// 192(168) bit key.
		memcpy(k1, key, DES_KEY_SIZE);
		memcpy(k2, key + DES_KEY_SIZE, DES_KEY_SIZE);
		memcpy(k3, key + DES_KEY_SIZE + DES_KEY_SIZE, DES_KEY_SIZE);
		break;
	default:
		return -1;
	}

	return 0;
}

static inline tdes_key *tdes_key_init_checked(void *ptr, byte_t k1[DES_KEY_SIZE], byte_t k2[DES_KEY_SIZE], byte_t k3[DES_KEY_SIZE])
{
	tdes_key *key = (tdes_key *)ptr;

	memset(key, 0, sizeof(tdes_key));

	des_key_expansion(key->rk1, k1);
	des_key_expansion(key->rk2, k2);
	des_key_expansion(key->rk3, k3);

	return key;
}

tdes_key *tdes_key_init(void *ptr, size_t size, byte_t k1[DES_KEY_SIZE], byte_t k2[DES_KEY_SIZE], byte_t k3[DES_KEY_SIZE], bool check)
{
	if (size < sizeof(tdes_key))
	{
		return NULL;
	}

	if (k1 == NULL || k2 == NULL || k3 == NULL)
	{
		return NULL;
	}

	if (check)
	{
		if (!check_des_key(k1) || !check_des_key(k2) || !check_des_key(k3))
		{
			return NULL;
		}
	}

	return tdes_key_init_checked(ptr, k1, k2, k3);
}

tdes_key *tdes_key_new(byte_t k1[DES_KEY_SIZE], byte_t k2[DES_KEY_SIZE], byte_t k3[DES_KEY_SIZE], bool check)
{
	tdes_key *key = NULL;

	if (k1 == NULL || k2 == NULL || k3 == NULL)
	{
		return NULL;
	}

	if (check)
	{
		if (!check_des_key(k1) || !check_des_key(k2) || !check_des_key(k3))
		{
			return NULL;
		}
	}

	key = (tdes_key *)malloc(sizeof(tdes_key));

	if (key == NULL)
	{
		return NULL;
	}

	return tdes_key_init_checked(key, k1, k2, k3);
}

void tdes_key_delete(tdes_key *key)
{
	// Zero the key for security reasons.
	memset(key, 0, sizeof(tdes_key));
	free(key);
}

void tdes_encrypt_block(tdes_key *key, byte_t plaintext[DES_BLOCK_SIZE], byte_t ciphertext[DES_BLOCK_SIZE])
{
	byte_t temp_plaintext[DES_BLOCK_SIZE], temp_ciphertext[DES_BLOCK_SIZE];

	memcpy(temp_plaintext, plaintext, DES_BLOCK_SIZE);

	des_encrypt_block(key->rk1, temp_plaintext, temp_ciphertext);
	des_decrypt_block(key->rk2, temp_ciphertext, temp_plaintext);
	des_encrypt_block(key->rk3, temp_plaintext, temp_ciphertext);

	memcpy(ciphertext, temp_ciphertext, DES_BLOCK_SIZE);
}

void tdes_decrypt_block(tdes_key *key, byte_t ciphertext[DES_BLOCK_SIZE], byte_t plaintext[DES_BLOCK_SIZE])
{
	byte_t temp_plaintext[DES_BLOCK_SIZE], temp_ciphertext[DES_BLOCK_SIZE];

	memcpy(temp_ciphertext, ciphertext, DES_BLOCK_SIZE);

	des_decrypt_block(key->rk3, temp_ciphertext, temp_plaintext);
	des_encrypt_block(key->rk2, temp_plaintext, temp_ciphertext);
	des_decrypt_block(key->rk1, temp_ciphertext, temp_plaintext);

	memcpy(plaintext, temp_plaintext, DES_BLOCK_SIZE);
}
