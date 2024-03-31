/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <aes.h>
#include <rotate.h>

// clang-format off
// S-box data
static const uint8_t SBOX[256] = 
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t INVSBOX[256] = 
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// Key rotation constants
static const uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
// clang-format on

#define SIZEOF_KEY_WORD 4

#define AES128_ROUNDS    10
#define AES128_KEY_WORDS 4

#define AES192_ROUNDS    12
#define AES192_KEY_WORDS 6

#define AES256_ROUNDS    14
#define AES256_KEY_WORDS 8

#define SUBWORD(W) SBOX[((W) >> 24) & 0xFF] << 24 | SBOX[((W) >> 16) & 0xFF] << 16 | SBOX[((W) >> 8) & 0xFF] << 8 | SBOX[(W) & 0xFF]

// Galois Field Multiplications
#define XTIME(A)  (((A) & 0X80) ? ((A) << 1) : (((A) << 1) ^ 0X1B))
#define X2TIME(A) (XTIME(XTIME((A))))
#define X3TIME(A) (XTIME(XTIME(XTIME((A)))))

#define GF2TIME(A) (XTIME(A))
#define GF3TIME(A) (XTIME(A) ^ (A))
#define GF9TIME(A) (X3TIME(A) ^ (A))
#define GFBTIME(A) (X3TIME(A) ^ XTIME(A) ^ (A))
#define GFDTIME(A) (X3TIME(A) ^ X2TIME(A) ^ (A))
#define GFETIME(A) (X3TIME(A) ^ X2TIME(A) ^ XTIME(A))

#define BLOCK_TRANSPOSE(S, B) \
	{                         \
		S[0] = B[0];          \
		S[1] = B[4];          \
		S[2] = B[8];          \
		S[3] = B[12];         \
		S[4] = B[1];          \
		S[5] = B[5];          \
		S[6] = B[9];          \
		S[7] = B[13];         \
		S[8] = B[2];          \
		S[9] = B[6];          \
		S[10] = B[10];        \
		S[11] = B[14];        \
		S[12] = B[3];         \
		S[13] = B[7];         \
		S[14] = B[11];        \
		S[15] = B[15];        \
	}

#define ADD_ROUND_KEY(K, S) \
	{                       \
		S[0] ^= K[0];       \
		S[1] ^= K[1];       \
		S[2] ^= K[2];       \
		S[3] ^= K[3];       \
		S[4] ^= K[4];       \
		S[5] ^= K[5];       \
		S[6] ^= K[6];       \
		S[7] ^= K[7];       \
		S[8] ^= K[8];       \
		S[9] ^= K[9];       \
		S[10] ^= K[10];     \
		S[11] ^= K[11];     \
		S[12] ^= K[12];     \
		S[13] ^= K[13];     \
		S[14] ^= K[14];     \
		S[15] ^= K[15];     \
	}

#define SUB_BYTES(S)         \
	{                        \
		S[0] = SBOX[S[0]];   \
		S[1] = SBOX[S[1]];   \
		S[2] = SBOX[S[2]];   \
		S[3] = SBOX[S[3]];   \
		S[4] = SBOX[S[4]];   \
		S[5] = SBOX[S[5]];   \
		S[6] = SBOX[S[6]];   \
		S[7] = SBOX[S[7]];   \
		S[8] = SBOX[S[8]];   \
		S[9] = SBOX[S[9]];   \
		S[10] = SBOX[S[10]]; \
		S[11] = SBOX[S[11]]; \
		S[12] = SBOX[S[12]]; \
		S[13] = SBOX[S[13]]; \
		S[14] = SBOX[S[14]]; \
		S[15] = SBOX[S[15]]; \
	}

#define INVSUB_BYTES(S)         \
	{                           \
		S[0] = INVSBOX[S[0]];   \
		S[1] = INVSBOX[S[1]];   \
		S[2] = INVSBOX[S[2]];   \
		S[3] = INVSBOX[S[3]];   \
		S[4] = INVSBOX[S[4]];   \
		S[5] = INVSBOX[S[5]];   \
		S[6] = INVSBOX[S[6]];   \
		S[7] = INVSBOX[S[7]];   \
		S[8] = INVSBOX[S[8]];   \
		S[9] = INVSBOX[S[9]];   \
		S[10] = INVSBOX[S[10]]; \
		S[11] = INVSBOX[S[11]]; \
		S[12] = INVSBOX[S[12]]; \
		S[13] = INVSBOX[S[13]]; \
		S[14] = INVSBOX[S[14]]; \
		S[15] = INVSBOX[S[15]]; \
	}

#define SHIFT_ROWS(S)                \
	{                                \
		uint32_t *W = (uint32_t *)S; \
		ROTR_32(W[1], 8);            \
		ROTR_32(W[2], 16);           \
		ROTR_32(W[3], 24);           \
	}

#define INVSHIFT_ROWS(S)             \
	{                                \
		uint32_t *W = (uint32_t *)S; \
		ROTL_32(W[1], 8);            \
		ROTL_32(W[2], 16);           \
		ROTL_32(W[3], 24);           \
	}

#define MIX_COLUMNS(S, T)                                          \
	{                                                              \
		memcpy(T, S, 16);                                          \
                                                                   \
		S[0] = GF2TIME(T[0]) ^ GF3TIME(T[4]) ^ (T[8]) ^ (T[12]);   \
		S[1] = GF2TIME(T[1]) ^ GF3TIME(T[5]) ^ (T[9]) ^ (T[13]);   \
		S[2] = GF2TIME(T[2]) ^ GF3TIME(T[6]) ^ (T[10]) ^ (T[14]);  \
		S[3] = GF2TIME(T[3]) ^ GF3TIME(T[7]) ^ (T[11]) ^ (T[15]);  \
                                                                   \
		S[4] = (T[0]) ^ GF2TIME(T[4]) ^ GF3TIME(T[8]) ^ (T[12]);   \
		S[5] = (T[1]) ^ GF2TIME(T[5]) ^ GF3TIME(T[9]) ^ (T[13]);   \
		S[6] = (T[2]) ^ GF2TIME(T[6]) ^ GF3TIME(T[10]) ^ (T[14]);  \
		S[7] = (T[3]) ^ GF2TIME(T[7]) ^ GF3TIME(T[11]) ^ (T[15]);  \
                                                                   \
		S[8] = (T[0]) ^ (T[4]) ^ GF2TIME(T[8]) ^ GF3TIME(T[12]);   \
		S[9] = (T[1]) ^ (T[5]) ^ GF2TIME(T[9]) ^ GF3TIME(T[13]);   \
		S[10] = (T[2]) ^ (T[6]) ^ GF2TIME(T[10]) ^ GF3TIME(T[14]); \
		S[11] = (T[3]) ^ (T[7]) ^ GF2TIME(T[11]) ^ GF3TIME(T[15]); \
                                                                   \
		S[12] = GF3TIME(T[0]) ^ (T[4]) ^ (T[8]) ^ GF2TIME(T[12]);  \
		S[13] = GF3TIME(T[1]) ^ (T[5]) ^ (T[9]) ^ GF2TIME(T[13]);  \
		S[14] = GF3TIME(T[2]) ^ (T[6]) ^ (T[10]) ^ GF2TIME(T[14]); \
		S[15] = GF3TIME(T[3]) ^ (T[7]) ^ (T[11]) ^ GF2TIME(T[15]); \
	}

#define INVMIX_COLUMNS(S, T)                                                     \
	{                                                                            \
		memcpy(T, S, 16);                                                        \
                                                                                 \
		S[0] = GFETIME(T[0]) ^ GFBTIME(T[4]) ^ GFDTIME(T[8]) ^ GF9TIME(T[12]);   \
		S[1] = GFETIME(T[1]) ^ GFBTIME(T[5]) ^ GFDTIME(T[9]) ^ GF9TIME(T[13]);   \
		S[2] = GFETIME(T[2]) ^ GFBTIME(T[6]) ^ GFDTIME(T[10]) ^ GF9TIME(T[14]);  \
		S[3] = GFETIME(T[3]) ^ GFBTIME(T[7]) ^ GFDTIME(T[11]) ^ GF9TIME(T[15]);  \
                                                                                 \
		S[4] = GF9TIME(T[0]) ^ GFETIME(T[4]) ^ GFBTIME(T[8]) ^ GFDTIME(T[12]);   \
		S[5] = GF9TIME(T[1]) ^ GFETIME(T[5]) ^ GFBTIME(T[9]) ^ GFDTIME(T[13]);   \
		S[6] = GF9TIME(T[2]) ^ GFETIME(T[6]) ^ GFBTIME(T[10]) ^ GFDTIME(T[14]);  \
		S[7] = GF9TIME(T[3]) ^ GFETIME(T[7]) ^ GFBTIME(T[11]) ^ GFDTIME(T[15]);  \
                                                                                 \
		S[8] = GFDTIME(T[0]) ^ GF9TIME(T[4]) ^ GFETIME(T[8]) ^ GFBTIME(T[12]);   \
		S[9] = GFDTIME(T[1]) ^ GF9TIME(T[5]) ^ GFETIME(T[9]) ^ GFBTIME(T[13]);   \
		S[10] = GFDTIME(T[2]) ^ GF9TIME(T[6]) ^ GFETIME(T[10]) ^ GFBTIME(T[14]); \
		S[11] = GFDTIME(T[3]) ^ GF9TIME(T[7]) ^ GFETIME(T[11]) ^ GFBTIME(T[15]); \
                                                                                 \
		S[12] = GFBTIME(T[0]) ^ GFDTIME(T[4]) ^ GF9TIME(T[8]) ^ GFETIME(T[12]);  \
		S[13] = GFBTIME(T[1]) ^ GFDTIME(T[5]) ^ GF9TIME(T[9]) ^ GFETIME(T[13]);  \
		S[14] = GFBTIME(T[2]) ^ GFDTIME(T[6]) ^ GF9TIME(T[10]) ^ GFETIME(T[14]); \
		S[15] = GFBTIME(T[3]) ^ GFDTIME(T[7]) ^ GF9TIME(T[11]) ^ GFETIME(T[15]); \
	}

static inline void rijndael_encrypt_step(aes_round_key key, byte_t state[16], byte_t temp[16])
{
	SUB_BYTES(state);
	SHIFT_ROWS(state);
	MIX_COLUMNS(state, temp);
	ADD_ROUND_KEY(key, state);
}

static inline void rijndael_decrypt_step(aes_round_key key, byte_t state[16], byte_t temp[16])
{
	ADD_ROUND_KEY(key, state);
	INVMIX_COLUMNS(state, temp);
	INVSHIFT_ROWS(state);
	INVSUB_BYTES(state);
}

static void rijndael128_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE])
{
	byte_t state[16], temp[16];

	BLOCK_TRANSPOSE(state, plaintext);

	// Start
	ADD_ROUND_KEY(key->round_key[0], state);

	// Rounds 1 - 9
	rijndael_encrypt_step(key->round_key[1], state, temp);
	rijndael_encrypt_step(key->round_key[2], state, temp);
	rijndael_encrypt_step(key->round_key[3], state, temp);
	rijndael_encrypt_step(key->round_key[4], state, temp);
	rijndael_encrypt_step(key->round_key[5], state, temp);
	rijndael_encrypt_step(key->round_key[6], state, temp);
	rijndael_encrypt_step(key->round_key[7], state, temp);
	rijndael_encrypt_step(key->round_key[8], state, temp);
	rijndael_encrypt_step(key->round_key[9], state, temp);

	// End
	SUB_BYTES(state);
	SHIFT_ROWS(state);
	ADD_ROUND_KEY(key->round_key[10], state);

	BLOCK_TRANSPOSE(ciphertext, state);
}

static void rijndael128_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE])
{
	byte_t state[16], temp[16];

	BLOCK_TRANSPOSE(state, ciphertext);

	// Start
	ADD_ROUND_KEY(key->round_key[10], state);
	INVSHIFT_ROWS(state);
	INVSUB_BYTES(state);

	// Rounds 9 - 1
	rijndael_decrypt_step(key->round_key[9], state, temp);
	rijndael_decrypt_step(key->round_key[8], state, temp);
	rijndael_decrypt_step(key->round_key[7], state, temp);
	rijndael_decrypt_step(key->round_key[6], state, temp);
	rijndael_decrypt_step(key->round_key[5], state, temp);
	rijndael_decrypt_step(key->round_key[4], state, temp);
	rijndael_decrypt_step(key->round_key[3], state, temp);
	rijndael_decrypt_step(key->round_key[2], state, temp);
	rijndael_decrypt_step(key->round_key[1], state, temp);

	// End
	ADD_ROUND_KEY(key->round_key[0], state);

	BLOCK_TRANSPOSE(plaintext, state);
}

static void rijndael192_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE])
{
	byte_t state[16], temp[16];

	BLOCK_TRANSPOSE(state, plaintext);

	// Start
	ADD_ROUND_KEY(key->round_key[0], state);

	// Rounds 1 - 11
	rijndael_encrypt_step(key->round_key[1], state, temp);
	rijndael_encrypt_step(key->round_key[2], state, temp);
	rijndael_encrypt_step(key->round_key[3], state, temp);
	rijndael_encrypt_step(key->round_key[4], state, temp);
	rijndael_encrypt_step(key->round_key[5], state, temp);
	rijndael_encrypt_step(key->round_key[6], state, temp);
	rijndael_encrypt_step(key->round_key[7], state, temp);
	rijndael_encrypt_step(key->round_key[8], state, temp);
	rijndael_encrypt_step(key->round_key[9], state, temp);
	rijndael_encrypt_step(key->round_key[10], state, temp);
	rijndael_encrypt_step(key->round_key[11], state, temp);

	// End
	SUB_BYTES(state);
	SHIFT_ROWS(state);
	ADD_ROUND_KEY(key->round_key[12], state);

	BLOCK_TRANSPOSE(ciphertext, state);
}

static void rijndael192_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE])
{
	byte_t state[16], temp[16];

	BLOCK_TRANSPOSE(state, ciphertext);

	// Start
	ADD_ROUND_KEY(key->round_key[12], state);
	INVSHIFT_ROWS(state);
	INVSUB_BYTES(state);

	// Rounds 11 - 1
	rijndael_decrypt_step(key->round_key[11], state, temp);
	rijndael_decrypt_step(key->round_key[10], state, temp);
	rijndael_decrypt_step(key->round_key[9], state, temp);
	rijndael_decrypt_step(key->round_key[8], state, temp);
	rijndael_decrypt_step(key->round_key[7], state, temp);
	rijndael_decrypt_step(key->round_key[6], state, temp);
	rijndael_decrypt_step(key->round_key[5], state, temp);
	rijndael_decrypt_step(key->round_key[4], state, temp);
	rijndael_decrypt_step(key->round_key[3], state, temp);
	rijndael_decrypt_step(key->round_key[2], state, temp);
	rijndael_decrypt_step(key->round_key[1], state, temp);

	// End
	ADD_ROUND_KEY(key->round_key[0], state);

	BLOCK_TRANSPOSE(plaintext, state);
}

static void rijndael256_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE])
{
	byte_t state[16], temp[16];

	BLOCK_TRANSPOSE(state, plaintext);

	// Start
	ADD_ROUND_KEY(key->round_key[0], state);

	// Rounds 1 - 13
	rijndael_encrypt_step(key->round_key[1], state, temp);
	rijndael_encrypt_step(key->round_key[2], state, temp);
	rijndael_encrypt_step(key->round_key[3], state, temp);
	rijndael_encrypt_step(key->round_key[4], state, temp);
	rijndael_encrypt_step(key->round_key[5], state, temp);
	rijndael_encrypt_step(key->round_key[6], state, temp);
	rijndael_encrypt_step(key->round_key[7], state, temp);
	rijndael_encrypt_step(key->round_key[8], state, temp);
	rijndael_encrypt_step(key->round_key[9], state, temp);
	rijndael_encrypt_step(key->round_key[10], state, temp);
	rijndael_encrypt_step(key->round_key[11], state, temp);
	rijndael_encrypt_step(key->round_key[12], state, temp);
	rijndael_encrypt_step(key->round_key[13], state, temp);

	// End
	SUB_BYTES(state);
	SHIFT_ROWS(state);
	ADD_ROUND_KEY(key->round_key[14], state);

	BLOCK_TRANSPOSE(ciphertext, state);
}

static void rijndael256_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE])
{
	byte_t state[16], temp[16];

	BLOCK_TRANSPOSE(state, ciphertext);

	// Start
	ADD_ROUND_KEY(key->round_key[14], state);
	INVSHIFT_ROWS(state);
	INVSUB_BYTES(state);

	// Rounds 13 - 1
	rijndael_decrypt_step(key->round_key[13], state, temp);
	rijndael_decrypt_step(key->round_key[12], state, temp);
	rijndael_decrypt_step(key->round_key[11], state, temp);
	rijndael_decrypt_step(key->round_key[10], state, temp);
	rijndael_decrypt_step(key->round_key[9], state, temp);
	rijndael_decrypt_step(key->round_key[8], state, temp);
	rijndael_decrypt_step(key->round_key[7], state, temp);
	rijndael_decrypt_step(key->round_key[6], state, temp);
	rijndael_decrypt_step(key->round_key[5], state, temp);
	rijndael_decrypt_step(key->round_key[4], state, temp);
	rijndael_decrypt_step(key->round_key[3], state, temp);
	rijndael_decrypt_step(key->round_key[2], state, temp);
	rijndael_decrypt_step(key->round_key[1], state, temp);

	// End
	ADD_ROUND_KEY(key->round_key[0], state);

	BLOCK_TRANSPOSE(plaintext, state);
}

static void rijndael_key_expansion(aes_key *expanded_key, byte_t *actual_key)
{
	const uint8_t nb = 4;
	uint8_t nk, nr;
	uint32_t temp;
	uint32_t word[60];

	switch (expanded_key->type)
	{
	case AES128:
		nk = AES128_KEY_WORDS;
		nr = AES128_ROUNDS;
	case AES192:
		nk = AES192_KEY_WORDS;
		nr = AES192_ROUNDS;
	case AES256:
		nk = AES256_KEY_WORDS;
		nr = AES256_ROUNDS;
	}

	// Copy the key first.
	memcpy(word, actual_key, nk * SIZEOF_KEY_WORD);

	for (uint8_t i = nk; i < nb * (nr + 1); ++i)
	{
		temp = word[i - 1];

		if (i % nk == 0)
		{
			temp = SUBWORD(ROTL_32(temp, 8)) ^ RCON[i / nk];
		}
		else if (nk > 6 && i % 4 == 0)
		{
			temp = SUBWORD(temp);
		}

		word[i] = word[i - nk] ^ temp;
	}

	// Transpose each round key
	for (uint8_t i = 0; i < nr + 1; ++i)
	{
		byte_t *bytes = (byte_t *)&word[i * 4];
		BLOCK_TRANSPOSE(expanded_key->round_key[i], bytes);
	}
}

aes_key *new_aes_key(aes_type type, byte_t *key)
{
	aes_key *expanded_key = NULL;

	if (type != AES128 && type != AES192 && type != AES256)
	{
		return NULL;
	}

	expanded_key = (aes_key *)malloc(sizeof(aes_key));

	if (key == NULL)
	{
		return NULL;
	}

	expanded_key->type = type;
	rijndael_key_expansion(expanded_key, key);

	return expanded_key;
}

void delete_aes_key(aes_key *key)
{
	// Zero the key for security reasons.
	memset(key, 0, sizeof(aes_key));
	free(key);
}

void aes_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE])
{
	switch (key->type)
	{
	case AES128:
		return rijndael128_encrypt_block(key, plaintext, ciphertext);
	case AES192:
		return rijndael192_encrypt_block(key, plaintext, ciphertext);
	case AES256:
		return rijndael256_encrypt_block(key, plaintext, ciphertext);
	}
}

void aes_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE])
{
	switch (key->type)
	{
	case AES128:
		return rijndael128_decrypt_block(key, ciphertext, plaintext);
	case AES192:
		return rijndael192_decrypt_block(key, ciphertext, plaintext);
	case AES256:
		return rijndael256_decrypt_block(key, ciphertext, plaintext);
	}
}
