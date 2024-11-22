/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <aes.h>
#include <rotate.h>

// See NIST FIPS-197 Advanced Encryption Standard (AES)

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
static const uint8_t RCON[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

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
// Residue polymnial x^8 + x^4 + x^3 + x + 1
static inline byte_t xtime(byte_t x)
{
	return x & 0x80 ? ((x << 1) ^ 0x1B) : (x << 1);
}

#define XTIME(A)  (xtime(A))
#define X2TIME(A) (XTIME(XTIME((A))))
#define X3TIME(A) (XTIME(XTIME(XTIME((A)))))

#define GF2TIME(A) (XTIME(A))
#define GF3TIME(A) (XTIME(A) ^ (A))
#define GF9TIME(A) (X3TIME(A) ^ (A))
#define GFBTIME(A) (X3TIME(A) ^ XTIME(A) ^ (A))
#define GFDTIME(A) (X3TIME(A) ^ X2TIME(A) ^ (A))
#define GFETIME(A) (X3TIME(A) ^ X2TIME(A) ^ XTIME(A))

static inline void block_transpose(byte_t state[AES_BLOCK_SIZE], byte_t block[AES_BLOCK_SIZE])
{
	state[0] = block[0];
	state[1] = block[4];
	state[2] = block[8];
	state[3] = block[12];
	state[4] = block[1];
	state[5] = block[5];
	state[6] = block[9];
	state[7] = block[13];
	state[8] = block[2];
	state[9] = block[6];
	state[10] = block[10];
	state[11] = block[14];
	state[12] = block[3];
	state[13] = block[7];
	state[14] = block[11];
	state[15] = block[15];
}

static inline void add_round_key(byte_t state[AES_BLOCK_SIZE], aes_round_key key)
{
	uint64_t *ps = (uint64_t *)state;
	uint64_t *pk = (uint64_t *)key;

	// Use 2 64-bit XORs
	ps[0] ^= pk[0];
	ps[1] ^= pk[1];
}

static inline void sub_bytes(byte_t state[AES_BLOCK_SIZE])
{
	state[0] = SBOX[state[0]];
	state[1] = SBOX[state[1]];
	state[2] = SBOX[state[2]];
	state[3] = SBOX[state[3]];
	state[4] = SBOX[state[4]];
	state[5] = SBOX[state[5]];
	state[6] = SBOX[state[6]];
	state[7] = SBOX[state[7]];
	state[8] = SBOX[state[8]];
	state[9] = SBOX[state[9]];
	state[10] = SBOX[state[10]];
	state[11] = SBOX[state[11]];
	state[12] = SBOX[state[12]];
	state[13] = SBOX[state[13]];
	state[14] = SBOX[state[14]];
	state[15] = SBOX[state[15]];
}

static inline void invsub_bytes(byte_t state[AES_BLOCK_SIZE])
{
	state[0] = INVSBOX[state[0]];
	state[1] = INVSBOX[state[1]];
	state[2] = INVSBOX[state[2]];
	state[3] = INVSBOX[state[3]];
	state[4] = INVSBOX[state[4]];
	state[5] = INVSBOX[state[5]];
	state[6] = INVSBOX[state[6]];
	state[7] = INVSBOX[state[7]];
	state[8] = INVSBOX[state[8]];
	state[9] = INVSBOX[state[9]];
	state[10] = INVSBOX[state[10]];
	state[11] = INVSBOX[state[11]];
	state[12] = INVSBOX[state[12]];
	state[13] = INVSBOX[state[13]];
	state[14] = INVSBOX[state[14]];
	state[15] = INVSBOX[state[15]];
}

static inline void shift_rows(byte_t state[AES_BLOCK_SIZE])
{
	uint32_t *dword = (uint32_t *)state;

	dword[1] = ROTR_32(dword[1], 8);
	dword[2] = ROTR_32(dword[2], 16);
	dword[3] = ROTR_32(dword[3], 24);
}

static inline void invshift_rows(byte_t state[AES_BLOCK_SIZE])
{
	uint32_t *dword = (uint32_t *)state;

	dword[1] = ROTL_32(dword[1], 8);
	dword[2] = ROTL_32(dword[2], 16);
	dword[3] = ROTL_32(dword[3], 24);
}

static inline void mix_columns(byte_t state[AES_BLOCK_SIZE])
{
	byte_t temp[AES_BLOCK_SIZE];

	memcpy(temp, state, AES_BLOCK_SIZE);

	state[0] = GF2TIME(temp[0]) ^ GF3TIME(temp[4]) ^ (temp[8]) ^ (temp[12]);
	state[1] = GF2TIME(temp[1]) ^ GF3TIME(temp[5]) ^ (temp[9]) ^ (temp[13]);
	state[2] = GF2TIME(temp[2]) ^ GF3TIME(temp[6]) ^ (temp[10]) ^ (temp[14]);
	state[3] = GF2TIME(temp[3]) ^ GF3TIME(temp[7]) ^ (temp[11]) ^ (temp[15]);

	state[4] = (temp[0]) ^ GF2TIME(temp[4]) ^ GF3TIME(temp[8]) ^ (temp[12]);
	state[5] = (temp[1]) ^ GF2TIME(temp[5]) ^ GF3TIME(temp[9]) ^ (temp[13]);
	state[6] = (temp[2]) ^ GF2TIME(temp[6]) ^ GF3TIME(temp[10]) ^ (temp[14]);
	state[7] = (temp[3]) ^ GF2TIME(temp[7]) ^ GF3TIME(temp[11]) ^ (temp[15]);

	state[8] = (temp[0]) ^ (temp[4]) ^ GF2TIME(temp[8]) ^ GF3TIME(temp[12]);
	state[9] = (temp[1]) ^ (temp[5]) ^ GF2TIME(temp[9]) ^ GF3TIME(temp[13]);
	state[10] = (temp[2]) ^ (temp[6]) ^ GF2TIME(temp[10]) ^ GF3TIME(temp[14]);
	state[11] = (temp[3]) ^ (temp[7]) ^ GF2TIME(temp[11]) ^ GF3TIME(temp[15]);

	state[12] = GF3TIME(temp[0]) ^ (temp[4]) ^ (temp[8]) ^ GF2TIME(temp[12]);
	state[13] = GF3TIME(temp[1]) ^ (temp[5]) ^ (temp[9]) ^ GF2TIME(temp[13]);
	state[14] = GF3TIME(temp[2]) ^ (temp[6]) ^ (temp[10]) ^ GF2TIME(temp[14]);
	state[15] = GF3TIME(temp[3]) ^ (temp[7]) ^ (temp[11]) ^ GF2TIME(temp[15]);
}

static inline void invmix_columns(byte_t state[AES_BLOCK_SIZE])
{
	byte_t temp[AES_BLOCK_SIZE];

	memcpy(temp, state, AES_BLOCK_SIZE);

	state[0] = GFETIME(temp[0]) ^ GFBTIME(temp[4]) ^ GFDTIME(temp[8]) ^ GF9TIME(temp[12]);
	state[1] = GFETIME(temp[1]) ^ GFBTIME(temp[5]) ^ GFDTIME(temp[9]) ^ GF9TIME(temp[13]);
	state[2] = GFETIME(temp[2]) ^ GFBTIME(temp[6]) ^ GFDTIME(temp[10]) ^ GF9TIME(temp[14]);
	state[3] = GFETIME(temp[3]) ^ GFBTIME(temp[7]) ^ GFDTIME(temp[11]) ^ GF9TIME(temp[15]);

	state[4] = GF9TIME(temp[0]) ^ GFETIME(temp[4]) ^ GFBTIME(temp[8]) ^ GFDTIME(temp[12]);
	state[5] = GF9TIME(temp[1]) ^ GFETIME(temp[5]) ^ GFBTIME(temp[9]) ^ GFDTIME(temp[13]);
	state[6] = GF9TIME(temp[2]) ^ GFETIME(temp[6]) ^ GFBTIME(temp[10]) ^ GFDTIME(temp[14]);
	state[7] = GF9TIME(temp[3]) ^ GFETIME(temp[7]) ^ GFBTIME(temp[11]) ^ GFDTIME(temp[15]);

	state[8] = GFDTIME(temp[0]) ^ GF9TIME(temp[4]) ^ GFETIME(temp[8]) ^ GFBTIME(temp[12]);
	state[9] = GFDTIME(temp[1]) ^ GF9TIME(temp[5]) ^ GFETIME(temp[9]) ^ GFBTIME(temp[13]);
	state[10] = GFDTIME(temp[2]) ^ GF9TIME(temp[6]) ^ GFETIME(temp[10]) ^ GFBTIME(temp[14]);
	state[11] = GFDTIME(temp[3]) ^ GF9TIME(temp[7]) ^ GFETIME(temp[11]) ^ GFBTIME(temp[15]);

	state[12] = GFBTIME(temp[0]) ^ GFDTIME(temp[4]) ^ GF9TIME(temp[8]) ^ GFETIME(temp[12]);
	state[13] = GFBTIME(temp[1]) ^ GFDTIME(temp[5]) ^ GF9TIME(temp[9]) ^ GFETIME(temp[13]);
	state[14] = GFBTIME(temp[2]) ^ GFDTIME(temp[6]) ^ GF9TIME(temp[10]) ^ GFETIME(temp[14]);
	state[15] = GFBTIME(temp[3]) ^ GFDTIME(temp[7]) ^ GF9TIME(temp[11]) ^ GFETIME(temp[15]);
}

static inline void rijndael_encrypt_step(aes_round_key key, byte_t state[AES_BLOCK_SIZE])
{
	sub_bytes(state);
	shift_rows(state);
	mix_columns(state);
	add_round_key(state, key);
}

static inline void rijndael_decrypt_step(aes_round_key key, byte_t state[AES_BLOCK_SIZE])
{
	add_round_key(state, key);
	invmix_columns(state);
	invshift_rows(state);
	invsub_bytes(state);
}

void aes128_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE])
{
	byte_t state[AES_BLOCK_SIZE];

	block_transpose(state, plaintext);

	// Start
	add_round_key(state, key->round_key[0]);

	// Rounds 1 - 9
	rijndael_encrypt_step(key->round_key[1], state);
	rijndael_encrypt_step(key->round_key[2], state);
	rijndael_encrypt_step(key->round_key[3], state);
	rijndael_encrypt_step(key->round_key[4], state);
	rijndael_encrypt_step(key->round_key[5], state);
	rijndael_encrypt_step(key->round_key[6], state);
	rijndael_encrypt_step(key->round_key[7], state);
	rijndael_encrypt_step(key->round_key[8], state);
	rijndael_encrypt_step(key->round_key[9], state);

	// End
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, key->round_key[10]);

	block_transpose(ciphertext, state);
}

void aes128_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE])
{
	byte_t state[AES_BLOCK_SIZE];

	block_transpose(state, ciphertext);

	// Start
	add_round_key(state, key->round_key[10]);
	invshift_rows(state);
	invsub_bytes(state);

	// Rounds 9 - 1
	rijndael_decrypt_step(key->round_key[9], state);
	rijndael_decrypt_step(key->round_key[8], state);
	rijndael_decrypt_step(key->round_key[7], state);
	rijndael_decrypt_step(key->round_key[6], state);
	rijndael_decrypt_step(key->round_key[5], state);
	rijndael_decrypt_step(key->round_key[4], state);
	rijndael_decrypt_step(key->round_key[3], state);
	rijndael_decrypt_step(key->round_key[2], state);
	rijndael_decrypt_step(key->round_key[1], state);

	// End
	add_round_key(state, key->round_key[0]);

	block_transpose(plaintext, state);
}

void aes192_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE])
{
	byte_t state[AES_BLOCK_SIZE];

	block_transpose(state, plaintext);

	// Start
	add_round_key(state, key->round_key[0]);

	// Rounds 1 - 11
	rijndael_encrypt_step(key->round_key[1], state);
	rijndael_encrypt_step(key->round_key[2], state);
	rijndael_encrypt_step(key->round_key[3], state);
	rijndael_encrypt_step(key->round_key[4], state);
	rijndael_encrypt_step(key->round_key[5], state);
	rijndael_encrypt_step(key->round_key[6], state);
	rijndael_encrypt_step(key->round_key[7], state);
	rijndael_encrypt_step(key->round_key[8], state);
	rijndael_encrypt_step(key->round_key[9], state);
	rijndael_encrypt_step(key->round_key[10], state);
	rijndael_encrypt_step(key->round_key[11], state);

	// End
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, key->round_key[12]);

	block_transpose(ciphertext, state);
}

void aes192_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE])
{
	byte_t state[AES_BLOCK_SIZE];

	block_transpose(state, ciphertext);

	// Start
	add_round_key(state, key->round_key[12]);
	invshift_rows(state);
	invsub_bytes(state);

	// Rounds 11 - 1
	rijndael_decrypt_step(key->round_key[11], state);
	rijndael_decrypt_step(key->round_key[10], state);
	rijndael_decrypt_step(key->round_key[9], state);
	rijndael_decrypt_step(key->round_key[8], state);
	rijndael_decrypt_step(key->round_key[7], state);
	rijndael_decrypt_step(key->round_key[6], state);
	rijndael_decrypt_step(key->round_key[5], state);
	rijndael_decrypt_step(key->round_key[4], state);
	rijndael_decrypt_step(key->round_key[3], state);
	rijndael_decrypt_step(key->round_key[2], state);
	rijndael_decrypt_step(key->round_key[1], state);

	// End
	add_round_key(state, key->round_key[0]);

	block_transpose(plaintext, state);
}

void aes256_encrypt_block(aes_key *key, byte_t plaintext[AES_BLOCK_SIZE], byte_t ciphertext[AES_BLOCK_SIZE])
{
	byte_t state[AES_BLOCK_SIZE];

	block_transpose(state, plaintext);

	// Start
	add_round_key(state, key->round_key[0]);

	// Rounds 1 - 13
	rijndael_encrypt_step(key->round_key[1], state);
	rijndael_encrypt_step(key->round_key[2], state);
	rijndael_encrypt_step(key->round_key[3], state);
	rijndael_encrypt_step(key->round_key[4], state);
	rijndael_encrypt_step(key->round_key[5], state);
	rijndael_encrypt_step(key->round_key[6], state);
	rijndael_encrypt_step(key->round_key[7], state);
	rijndael_encrypt_step(key->round_key[8], state);
	rijndael_encrypt_step(key->round_key[9], state);
	rijndael_encrypt_step(key->round_key[10], state);
	rijndael_encrypt_step(key->round_key[11], state);
	rijndael_encrypt_step(key->round_key[12], state);
	rijndael_encrypt_step(key->round_key[13], state);

	// End
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, key->round_key[14]);

	block_transpose(ciphertext, state);
}

void aes256_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE])
{
	byte_t state[AES_BLOCK_SIZE];

	block_transpose(state, ciphertext);

	// Start
	add_round_key(state, key->round_key[14]);
	invshift_rows(state);
	invsub_bytes(state);

	// Rounds 13 - 1
	rijndael_decrypt_step(key->round_key[13], state);
	rijndael_decrypt_step(key->round_key[12], state);
	rijndael_decrypt_step(key->round_key[11], state);
	rijndael_decrypt_step(key->round_key[10], state);
	rijndael_decrypt_step(key->round_key[9], state);
	rijndael_decrypt_step(key->round_key[8], state);
	rijndael_decrypt_step(key->round_key[7], state);
	rijndael_decrypt_step(key->round_key[6], state);
	rijndael_decrypt_step(key->round_key[5], state);
	rijndael_decrypt_step(key->round_key[4], state);
	rijndael_decrypt_step(key->round_key[3], state);
	rijndael_decrypt_step(key->round_key[2], state);
	rijndael_decrypt_step(key->round_key[1], state);

	// End
	add_round_key(state, key->round_key[0]);

	block_transpose(plaintext, state);
}

static void rijndael_key_expansion(aes_key *expanded_key, void *actual_key)
{
	const uint8_t nb = 4;
	uint8_t nk = 0, nr = 0;
	uint32_t temp = 0;
	uint32_t word[60];

	switch (expanded_key->type)
	{
	case AES128:
		nk = AES128_KEY_WORDS;
		nr = AES128_ROUNDS;
		break;
	case AES192:
		nk = AES192_KEY_WORDS;
		nr = AES192_ROUNDS;
		break;
	case AES256:
		nk = AES256_KEY_WORDS;
		nr = AES256_ROUNDS;
		break;
	}

	// Copy the key first.
	memcpy(word, actual_key, nk * SIZEOF_KEY_WORD);

	for (uint8_t i = nk; i < nb * (nr + 1); ++i)
	{
		temp = word[i - 1];

		if (i % nk == 0)
		{
			temp = SUBWORD(ROTR_32(temp, 8)) ^ RCON[i / nk];
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
		block_transpose(expanded_key->round_key[i], bytes);
	}
}

static inline aes_key *aes_key_init_checked(void *ptr, aes_type type, void *key)
{
	aes_key *expanded_key = (aes_key *)ptr;

	memset(expanded_key, 0, sizeof(aes_key));
	expanded_key->type = type;
	rijndael_key_expansion(expanded_key, key);

	return expanded_key;
}

aes_key *aes_key_init(void *ptr, size_t size, aes_type type, void *key, size_t key_size)
{
	size_t required_key_size = 0;

	if (size < sizeof(aes_key))
	{
		return NULL;
	}

	switch (type)
	{
	case AES128:
		required_key_size = AES128_KEY_SIZE;
		break;
	case AES192:
		required_key_size = AES192_KEY_SIZE;
		break;
	case AES256:
		required_key_size = AES256_KEY_SIZE;
		break;
	default:
		return NULL;
	}

	if (key_size != required_key_size)
	{
		return NULL;
	}

	return aes_key_init_checked(ptr, type, key);
}

aes_key *aes_key_new(aes_type type, void *key, size_t key_size)
{
	aes_key *expanded_key = NULL;
	size_t required_key_size = 0;

	switch (type)
	{
	case AES128:
		required_key_size = AES128_KEY_SIZE;
		break;
	case AES192:
		required_key_size = AES192_KEY_SIZE;
		break;
	case AES256:
		required_key_size = AES256_KEY_SIZE;
		break;
	default:
		return NULL;
	}

	if (key_size != required_key_size)
	{
		return NULL;
	}

	expanded_key = (aes_key *)malloc(sizeof(aes_key));

	if (expanded_key == NULL)
	{
		return NULL;
	}

	return aes_key_init_checked(expanded_key, type, key);
}

void aes_key_delete(aes_key *key)
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
		return aes128_encrypt_block(key, plaintext, ciphertext);
	case AES192:
		return aes192_encrypt_block(key, plaintext, ciphertext);
	case AES256:
		return aes256_encrypt_block(key, plaintext, ciphertext);
	}
}

void aes_decrypt_block(aes_key *key, byte_t ciphertext[AES_BLOCK_SIZE], byte_t plaintext[AES_BLOCK_SIZE])
{
	switch (key->type)
	{
	case AES128:
		return aes128_decrypt_block(key, ciphertext, plaintext);
	case AES192:
		return aes192_decrypt_block(key, ciphertext, plaintext);
	case AES256:
		return aes256_decrypt_block(key, ciphertext, plaintext);
	}
}
