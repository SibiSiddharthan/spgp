/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <camellia.h>
#include <byteswap.h>
#include <rotate.h>

// See RFC 3713: A Description of the Camellia Encryption Algorithm

// SBOX data
// clang-format off
static const uint8_t SBOX[256] = 
{
	0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C, 0xAE, 0x41,
	0x23, 0xEF, 0x6B, 0x93, 0x45, 0x19, 0xA5, 0x21, 0xED, 0x0E, 0x4F, 0x4E, 0x1D, 0x65, 0x92, 0xBD,
	0x86, 0xB8, 0xAF, 0x8F, 0x7C, 0xEB, 0x1F, 0xCE, 0x3E, 0x30, 0xDC, 0x5F,	0x5E, 0xC5, 0x0B, 0x1A,
	0xA6, 0xE1, 0x39, 0xCA, 0xD5, 0x47, 0x5D, 0x3D, 0xD9, 0x01, 0x5A, 0xD6, 0x51, 0x56, 0x6C, 0x4D,
	0x8B, 0x0D,	0x9A, 0x66, 0xFB, 0xCC, 0xB0, 0x2D, 0x74, 0x12, 0x2B, 0x20, 0xF0, 0xB1, 0x84, 0x99,
	0xDF, 0x4C, 0xCB, 0xC2, 0x34, 0x7E, 0x76, 0x05,	0x6D, 0xB7, 0xA9, 0x31, 0xD1, 0x17, 0x04, 0xD7,
	0x14, 0x58, 0x3A, 0x61, 0xDE, 0x1B, 0x11, 0x1C, 0x32, 0x0F, 0x9C, 0x16, 0x53, 0x18,	0xF2, 0x22,
	0xFE, 0x44, 0xCF, 0xB2, 0xC3, 0xB5, 0x7A, 0x91, 0x24, 0x08, 0xE8, 0xA8, 0x60, 0xFC, 0x69, 0x50,
	0xAA, 0xD0, 0xA0, 0x7D,	0xA1, 0x89, 0x62, 0x97, 0x54, 0x5B, 0x1E, 0x95, 0xE0, 0xFF, 0x64, 0xD2,
	0x10, 0xC4, 0x00, 0x48, 0xA3, 0xF7, 0x75, 0xDB, 0x8A, 0x03,	0xE6, 0xDA, 0x09, 0x3F, 0xDD, 0x94,
	0x87, 0x5C, 0x83, 0x02, 0xCD, 0x4A, 0x90, 0x33, 0x73, 0x67, 0xF6, 0xF3, 0x9D, 0x7F, 0xBF, 0xE2,
	0x52, 0x9B, 0xD8, 0x26, 0xC8, 0x37, 0xC6, 0x3B, 0x81, 0x96, 0x6F, 0x4B, 0x13, 0xBE, 0x63, 0x2E,
	0xE9, 0x79, 0xA7, 0x8C, 0x9F, 0x6E,	0xBC, 0x8E, 0x29, 0xF5, 0xF9, 0xB6, 0x2F, 0xFD, 0xB4, 0x59,
	0x78, 0x98, 0x06, 0x6A, 0xE7, 0x46, 0x71, 0xBA, 0xD4, 0x25, 0xAB, 0x42,	0x88, 0xA2, 0x8D, 0xFA,
	0x72, 0x07, 0xB9, 0x55, 0xF8, 0xEE, 0xAC, 0x0A, 0x36, 0x49, 0x2A, 0x68, 0x3C, 0x38, 0xF1, 0xA4,
	0x40, 0x28,	0xD3, 0x7B, 0xBB, 0xC9, 0x43, 0xC1, 0x15, 0xE3, 0xAD, 0xF4, 0x77, 0xC7, 0x80, 0x9E
};
// clang-format on

#define SBOX1(x) SBOX[(x)]
#define SBOX2(x) ((SBOX[(x)] << 1) + (SBOX[(x)] >> 7))
#define SBOX3(x) ((SBOX[(x)] << 7) + (SBOX[(x)] >> 1))
#define SBOX4(x) SBOX[(((x) << 1) + ((x) >> 7) & 0xFF)]

// Key generation constants
static const uint64_t SIGMA_1 = 0xA09E667F3BCC908B;
static const uint64_t SIGMA_2 = 0xB67AE8584CAA73B2;
static const uint64_t SIGMA_3 = 0xC6EF372FE94F82BE;
static const uint64_t SIGMA_4 = 0x54FF53A5F1D36F1C;
static const uint64_t SIGMA_5 = 0x10E527FADE682D1D;
static const uint64_t SIGMA_6 = 0xB05688C2B3E6C1FD;

static inline uint64_t F(uint64_t in, uint64_t k)
{
	uint64_t x, y;
	uint8_t x1, x2, x3, x4, x5, x6, x7, x8;
	uint8_t y1, y2, y3, y4, y5, y6, y7, y8;
	uint8_t *xp, *yp;

	x = in ^ k;

	xp = (uint8_t *)&x;
	x1 = SBOX1(xp[0]);
	x2 = SBOX2(xp[1]);
	x3 = SBOX3(xp[2]);
	x4 = SBOX4(xp[3]);
	x5 = SBOX2(xp[4]);
	x6 = SBOX3(xp[5]);
	x7 = SBOX4(xp[6]);
	x8 = SBOX1(xp[7]);

	y1 = x1 ^ x3 ^ x4 ^ x6 ^ x7 ^ x8;
	y2 = x1 ^ x2 ^ x4 ^ x5 ^ x7 ^ x8;
	y3 = x1 ^ x2 ^ x3 ^ x5 ^ x6 ^ x8;
	y4 = x2 ^ x3 ^ x4 ^ x5 ^ x6 ^ x7;
	y5 = x1 ^ x2 ^ x6 ^ x7 ^ x8;
	y6 = x2 ^ x3 ^ x5 ^ x7 ^ x8;
	y7 = x3 ^ x4 ^ x5 ^ x6 ^ x8;
	y8 = x1 ^ x4 ^ x5 ^ x6 ^ x7;

	yp = (uint8_t *)&y;
	yp[0] = y1;
	yp[1] = y2;
	yp[2] = y3;
	yp[3] = y4;
	yp[4] = y5;
	yp[5] = y6;
	yp[6] = y7;
	yp[7] = y8;

	return y;
}

static inline uint64_t FL(uint64_t in, uint64_t k)
{
	uint32_t x1, x2;
	uint32_t k1, k2;
	uint64_t out;

	in = BSWAP_64(in);
	k = BSWAP_64(k);

	x1 = (in >> 32) & 0xFFFFFFFF;
	x2 = in & 0xFFFFFFFF;

	k1 = (k >> 32) & 0xFFFFFFFF;
	k2 = k & 0xFFFFFFFF;

	x2 = x2 ^ ROTL_32((x1 & k1), 1);
	x1 = x1 ^ (x2 | k2);

	out = x1;
	out = out << 32 | x2;

	out = BSWAP_64(out);
	return out;
}

static inline uint64_t FLINV(uint64_t in, uint64_t k)
{
	uint32_t y1, y2;
	uint32_t k1, k2;
	uint64_t out;

	in = BSWAP_64(in);
	k = BSWAP_64(k);

	y1 = (in >> 32) & 0xFFFFFFFF;
	y2 = in & 0xFFFFFFFF;

	k1 = (k >> 32) & 0xFFFFFFFF;
	k2 = k & 0xFFFFFFFF;

	y1 = y1 ^ (y2 | k2);
	y2 = y2 ^ ROTL_32((y1 & k1), 1);

	out = y1;
	out = out << 32 | y2;

	out = BSWAP_64(out);
	return out;
}

static void camellia128_encrypt_block(camellia_key *key, byte_t plaintext[CAMELLIA_BLOCK_SIZE], byte_t ciphertext[CAMELLIA_BLOCK_SIZE])
{
	uint64_t d1, d2;
	uint64_t *p;

	p = (uint64_t *)plaintext;
	d1 = p[0];
	d2 = p[1];

	// Prewhitening
	d1 ^= key->kw[0];
	d2 ^= key->kw[1];

	d2 = d2 ^ F(d1, key->k[0]); // Round 1
	d1 = d1 ^ F(d2, key->k[1]); // Round 2
	d2 = d2 ^ F(d1, key->k[2]); // Round 3
	d1 = d1 ^ F(d2, key->k[3]); // Round 4
	d2 = d2 ^ F(d1, key->k[4]); // Round 5
	d1 = d1 ^ F(d2, key->k[5]); // Round 6

	d1 = FL(d1, key->ke[0]);    // FL
	d2 = FLINV(d2, key->ke[1]); // FLINV

	d2 = d2 ^ F(d1, key->k[6]);  // Round 7
	d1 = d1 ^ F(d2, key->k[7]);  // Round 8
	d2 = d2 ^ F(d1, key->k[8]);  // Round 9
	d1 = d1 ^ F(d2, key->k[9]);  // Round 10
	d2 = d2 ^ F(d1, key->k[10]); // Round 11
	d1 = d1 ^ F(d2, key->k[11]); // Round 12

	d1 = FL(d1, key->ke[2]);    // FL
	d2 = FLINV(d2, key->ke[3]); // FLINV

	d2 = d2 ^ F(d1, key->k[12]); // Round 13
	d1 = d1 ^ F(d2, key->k[13]); // Round 14
	d2 = d2 ^ F(d1, key->k[14]); // Round 15
	d1 = d1 ^ F(d2, key->k[15]); // Round 16
	d2 = d2 ^ F(d1, key->k[16]); // Round 17
	d1 = d1 ^ F(d2, key->k[17]); // Round 18

	// Postwhitening
	d2 = d2 ^ key->kw[2];
	d1 = d1 ^ key->kw[3];

	p = (uint64_t *)ciphertext;
	p[0] = d2;
	p[1] = d1;
}

static void camellia128_decrypt_block(camellia_key *key, byte_t ciphertext[CAMELLIA_BLOCK_SIZE], byte_t plaintext[CAMELLIA_BLOCK_SIZE])
{
	uint64_t d1, d2;
	uint64_t *p;

	p = (uint64_t *)ciphertext;
	d1 = p[0];
	d2 = p[1];

	// Prewhitening
	d1 ^= key->kw[2];
	d2 ^= key->kw[3];

	d2 = d2 ^ F(d1, key->k[17]); // Round 1
	d1 = d1 ^ F(d2, key->k[16]); // Round 2
	d2 = d2 ^ F(d1, key->k[15]); // Round 3
	d1 = d1 ^ F(d2, key->k[14]); // Round 4
	d2 = d2 ^ F(d1, key->k[13]); // Round 5
	d1 = d1 ^ F(d2, key->k[12]); // Round 6

	d1 = FL(d1, key->ke[3]);    // FL
	d2 = FLINV(d2, key->ke[2]); // FLINV

	d2 = d2 ^ F(d1, key->k[11]); // Round 7
	d1 = d1 ^ F(d2, key->k[10]); // Round 8
	d2 = d2 ^ F(d1, key->k[9]);  // Round 9
	d1 = d1 ^ F(d2, key->k[8]);  // Round 10
	d2 = d2 ^ F(d1, key->k[7]);  // Round 11
	d1 = d1 ^ F(d2, key->k[6]);  // Round 12

	d1 = FL(d1, key->ke[1]);    // FL
	d2 = FLINV(d2, key->ke[0]); // FLINV

	d2 = d2 ^ F(d1, key->k[5]); // Round 13
	d1 = d1 ^ F(d2, key->k[4]); // Round 14
	d2 = d2 ^ F(d1, key->k[3]); // Round 15
	d1 = d1 ^ F(d2, key->k[2]); // Round 16
	d2 = d2 ^ F(d1, key->k[1]); // Round 17
	d1 = d1 ^ F(d2, key->k[0]); // Round 18

	// Postwhitening
	d2 = d2 ^ key->kw[0];
	d1 = d1 ^ key->kw[1];

	p = (uint64_t *)plaintext;
	p[0] = d2;
	p[1] = d1;
}

static void camellia256_encrypt_block(camellia_key *key, byte_t plaintext[CAMELLIA_BLOCK_SIZE], byte_t ciphertext[CAMELLIA_BLOCK_SIZE])
{
	uint64_t d1, d2;
	uint64_t *p;

	p = (uint64_t *)plaintext;
	d1 = p[0];
	d2 = p[1];

	// Prewhitening
	d1 ^= key->kw[0];
	d2 ^= key->kw[1];

	d2 = d2 ^ F(d1, key->k[0]); // Round 1
	d1 = d1 ^ F(d2, key->k[1]); // Round 2
	d2 = d2 ^ F(d1, key->k[2]); // Round 3
	d1 = d1 ^ F(d2, key->k[3]); // Round 4
	d2 = d2 ^ F(d1, key->k[4]); // Round 5
	d1 = d1 ^ F(d2, key->k[5]); // Round 6

	d1 = FL(d1, key->ke[0]);    // FL
	d2 = FLINV(d2, key->ke[1]); // FLINV

	d2 = d2 ^ F(d1, key->k[6]);  // Round 7
	d1 = d1 ^ F(d2, key->k[7]);  // Round 8
	d2 = d2 ^ F(d1, key->k[8]);  // Round 9
	d1 = d1 ^ F(d2, key->k[9]);  // Round 10
	d2 = d2 ^ F(d1, key->k[10]); // Round 11
	d1 = d1 ^ F(d2, key->k[11]); // Round 12

	d1 = FL(d1, key->ke[2]);    // FL
	d2 = FLINV(d2, key->ke[3]); // FLINV

	d2 = d2 ^ F(d1, key->k[12]); // Round 13
	d1 = d1 ^ F(d2, key->k[13]); // Round 14
	d2 = d2 ^ F(d1, key->k[14]); // Round 15
	d1 = d1 ^ F(d2, key->k[15]); // Round 16
	d2 = d2 ^ F(d1, key->k[16]); // Round 17
	d1 = d1 ^ F(d2, key->k[17]); // Round 18

	d1 = FL(d1, key->ke[4]);    // FL
	d2 = FLINV(d2, key->ke[5]); // FLINV

	d2 = d2 ^ F(d1, key->k[18]); // Round 19
	d1 = d1 ^ F(d2, key->k[19]); // Round 20
	d2 = d2 ^ F(d1, key->k[20]); // Round 21
	d1 = d1 ^ F(d2, key->k[21]); // Round 22
	d2 = d2 ^ F(d1, key->k[22]); // Round 23
	d1 = d1 ^ F(d2, key->k[23]); // Round 24

	// Postwhitening
	d2 = d2 ^ key->kw[2];
	d1 = d1 ^ key->kw[3];

	p = (uint64_t *)ciphertext;
	p[0] = d2;
	p[1] = d1;
}

static void camellia256_decrypt_block(camellia_key *key, byte_t ciphertext[CAMELLIA_BLOCK_SIZE], byte_t plaintext[CAMELLIA_BLOCK_SIZE])
{
	uint64_t d1, d2;
	uint64_t *p;

	p = (uint64_t *)ciphertext;
	d1 = p[0];
	d2 = p[1];

	// Prewhitening
	d1 ^= key->kw[2];
	d2 ^= key->kw[3];

	d2 = d2 ^ F(d1, key->k[23]); // Round 1
	d1 = d1 ^ F(d2, key->k[22]); // Round 2
	d2 = d2 ^ F(d1, key->k[21]); // Round 3
	d1 = d1 ^ F(d2, key->k[20]); // Round 4
	d2 = d2 ^ F(d1, key->k[19]); // Round 5
	d1 = d1 ^ F(d2, key->k[18]); // Round 6

	d1 = FL(d1, key->ke[5]);    // FL
	d2 = FLINV(d2, key->ke[4]); // FLINV

	d2 = d2 ^ F(d1, key->k[17]); // Round 7
	d1 = d1 ^ F(d2, key->k[16]); // Round 8
	d2 = d2 ^ F(d1, key->k[15]); // Round 9
	d1 = d1 ^ F(d2, key->k[14]); // Round 10
	d2 = d2 ^ F(d1, key->k[13]); // Round 11
	d1 = d1 ^ F(d2, key->k[12]); // Round 12

	d1 = FL(d1, key->ke[3]);    // FL
	d2 = FLINV(d2, key->ke[2]); // FLINV

	d2 = d2 ^ F(d1, key->k[11]); // Round 13
	d1 = d1 ^ F(d2, key->k[10]); // Round 14
	d2 = d2 ^ F(d1, key->k[9]);  // Round 15
	d1 = d1 ^ F(d2, key->k[8]);  // Round 16
	d2 = d2 ^ F(d1, key->k[7]);  // Round 17
	d1 = d1 ^ F(d2, key->k[6]);  // Round 18

	d1 = FL(d1, key->ke[1]);    // FL
	d2 = FLINV(d2, key->ke[0]); // FLINV

	d2 = d2 ^ F(d1, key->k[5]); // Round 19
	d1 = d1 ^ F(d2, key->k[4]); // Round 20
	d2 = d2 ^ F(d1, key->k[3]); // Round 21
	d1 = d1 ^ F(d2, key->k[2]); // Round 22
	d2 = d2 ^ F(d1, key->k[1]); // Round 23
	d1 = d1 ^ F(d2, key->k[0]); // Round 24

	// Postwhitening
	d2 = d2 ^ key->kw[0];
	d1 = d1 ^ key->kw[1];

	p = (uint64_t *)plaintext;
	p[0] = d2;
	p[1] = d1;
}

#define ROTL_128_HIGH(X, S) (((X[0] << S) | (X[1] >> (64 - S))))
#define ROTL_128_LOW(X, S)  (((X[1] << S) | (X[0] >> (64 - S))))
#define ROTR_128_HIGH(X, S) (((X[0] >> S) | (X[1] << (64 - S))))
#define ROTR_128_LOW(X, S)  (((X[1] >> S) | (X[0] << (64 - S))))

static void camellia_key_expansion(camellia_key *expanded_key, byte_t *actual_key)
{
	uint64_t kl[2], kr[2];
	uint64_t ka[2], kb[2];
	uint64_t d1, d2;
	uint64_t *p = (uint64_t *)actual_key;

	// Determine kl, kr
	switch (expanded_key->type)
	{
	case CAMELLIA128:
		kl[0] = (p[0]);
		kl[1] = (p[1]);
		kr[0] = 0;
		kr[1] = 0;
		break;
	case CAMELLIA192:
		kl[0] = (p[0]);
		kl[1] = (p[1]);
		kr[0] = (p[2]);
		kr[1] = (~p[2]);
		break;
	case CAMELLIA256:
		kl[0] = (p[0]);
		kl[1] = (p[1]);
		kr[0] = (p[2]);
		kr[1] = (p[3]);
		break;
	}

	// Determine ka, kb
	d1 = kl[0] ^ kr[0];
	d2 = kl[1] ^ kr[1];
	d2 = d2 ^ F(d1, BSWAP_64(SIGMA_1));
	d1 = d1 ^ F(d2, BSWAP_64(SIGMA_2));
	d1 = d1 ^ kl[0];
	d2 = d2 ^ kl[1];
	d2 = d2 ^ F(d1, BSWAP_64(SIGMA_3));
	d1 = d1 ^ F(d2, BSWAP_64(SIGMA_4));
	ka[0] = d1;
	ka[1] = d2;

	if (expanded_key->type != CAMELLIA128)
	{
		d1 = ka[0] ^ kr[0];
		d2 = ka[1] ^ kr[1];
		d2 = d2 ^ F(d1, BSWAP_64(SIGMA_5));
		d1 = d1 ^ F(d2, BSWAP_64(SIGMA_6));
		kb[0] = d1;
		kb[1] = d2;
	}

	kl[0] = BSWAP_64(kl[0]);
	kl[1] = BSWAP_64(kl[1]);

	kr[0] = BSWAP_64(kr[0]);
	kr[1] = BSWAP_64(kr[1]);

	ka[0] = BSWAP_64(ka[0]);
	ka[1] = BSWAP_64(ka[1]);

	kb[0] = BSWAP_64(kb[0]);
	kb[1] = BSWAP_64(kb[1]);

	// Key expansion
	switch (expanded_key->type)
	{
	case CAMELLIA128:
		expanded_key->kw[0] = BSWAP_64(kl[0]);
		expanded_key->kw[1] = BSWAP_64(kl[1]);
		expanded_key->kw[2] = BSWAP_64(ROTR_128_HIGH(ka, 17));
		expanded_key->kw[3] = BSWAP_64(ROTR_128_LOW(ka, 17));

		expanded_key->ke[0] = BSWAP_64(ROTL_128_HIGH(ka, 30));
		expanded_key->ke[1] = BSWAP_64(ROTL_128_LOW(ka, 30));
		expanded_key->ke[2] = BSWAP_64(ROTR_128_HIGH(kl, 51));
		expanded_key->ke[3] = BSWAP_64(ROTR_128_LOW(kl, 51));

		expanded_key->k[0] = BSWAP_64(ka[0]);
		expanded_key->k[1] = BSWAP_64(ka[1]);
		expanded_key->k[2] = BSWAP_64(ROTL_128_HIGH(kl, 15));
		expanded_key->k[3] = BSWAP_64(ROTL_128_LOW(kl, 15));
		expanded_key->k[4] = BSWAP_64(ROTL_128_HIGH(ka, 15));
		expanded_key->k[5] = BSWAP_64(ROTL_128_LOW(ka, 15));
		expanded_key->k[6] = BSWAP_64(ROTL_128_HIGH(kl, 45));
		expanded_key->k[7] = BSWAP_64(ROTL_128_LOW(kl, 45));
		expanded_key->k[8] = BSWAP_64(ROTL_128_HIGH(ka, 45));
		expanded_key->k[9] = BSWAP_64(ROTL_128_LOW(kl, 60));
		expanded_key->k[10] = BSWAP_64(ROTL_128_HIGH(ka, 60));
		expanded_key->k[11] = BSWAP_64(ROTL_128_LOW(ka, 60));
		expanded_key->k[12] = BSWAP_64(ROTR_128_HIGH(kl, 34));
		expanded_key->k[13] = BSWAP_64(ROTR_128_LOW(kl, 34));
		expanded_key->k[14] = BSWAP_64(ROTR_128_HIGH(ka, 34));
		expanded_key->k[15] = BSWAP_64(ROTR_128_LOW(ka, 34));
		expanded_key->k[16] = BSWAP_64(ROTR_128_HIGH(kl, 17));
		expanded_key->k[17] = BSWAP_64(ROTR_128_LOW(kl, 17));

		break;
	case CAMELLIA192:
	case CAMELLIA256:
		expanded_key->kw[0] = BSWAP_64(kl[0]);
		expanded_key->kw[1] = BSWAP_64(kl[1]);
		expanded_key->kw[2] = BSWAP_64(ROTR_128_HIGH(kb, 17));
		expanded_key->kw[3] = BSWAP_64(ROTR_128_LOW(kb, 17));

		expanded_key->ke[0] = BSWAP_64(ROTL_128_HIGH(kr, 30));
		expanded_key->ke[1] = BSWAP_64(ROTL_128_LOW(kr, 30));
		expanded_key->ke[2] = BSWAP_64(ROTL_128_HIGH(kl, 60));
		expanded_key->ke[3] = BSWAP_64(ROTL_128_LOW(kl, 60));
		expanded_key->ke[4] = BSWAP_64(ROTR_128_HIGH(ka, 51));
		expanded_key->ke[5] = BSWAP_64(ROTR_128_LOW(ka, 51));

		expanded_key->k[0] = BSWAP_64(kb[0]);
		expanded_key->k[1] = BSWAP_64(kb[1]);
		expanded_key->k[2] = BSWAP_64(ROTL_128_HIGH(kr, 15));
		expanded_key->k[3] = BSWAP_64(ROTL_128_LOW(kr, 15));
		expanded_key->k[4] = BSWAP_64(ROTL_128_HIGH(ka, 15));
		expanded_key->k[5] = BSWAP_64(ROTL_128_LOW(ka, 15));
		expanded_key->k[6] = BSWAP_64(ROTL_128_HIGH(kb, 30));
		expanded_key->k[7] = BSWAP_64(ROTL_128_LOW(kb, 30));
		expanded_key->k[8] = BSWAP_64(ROTL_128_HIGH(kl, 45));
		expanded_key->k[9] = BSWAP_64(ROTL_128_LOW(kl, 45));
		expanded_key->k[10] = BSWAP_64(ROTL_128_HIGH(ka, 45));
		expanded_key->k[11] = BSWAP_64(ROTL_128_LOW(ka, 45));
		expanded_key->k[12] = BSWAP_64(ROTL_128_HIGH(kr, 60));
		expanded_key->k[13] = BSWAP_64(ROTL_128_LOW(kr, 60));
		expanded_key->k[14] = BSWAP_64(ROTL_128_HIGH(kb, 60));
		expanded_key->k[15] = BSWAP_64(ROTL_128_LOW(kb, 60));
		expanded_key->k[16] = BSWAP_64(ROTR_128_HIGH(kl, 51));
		expanded_key->k[17] = BSWAP_64(ROTR_128_LOW(kl, 51));
		expanded_key->k[18] = BSWAP_64(ROTR_128_HIGH(kr, 34));
		expanded_key->k[19] = BSWAP_64(ROTR_128_LOW(kr, 34));
		expanded_key->k[20] = BSWAP_64(ROTR_128_HIGH(ka, 34));
		expanded_key->k[21] = BSWAP_64(ROTR_128_LOW(ka, 34));
		expanded_key->k[22] = BSWAP_64(ROTR_128_HIGH(kl, 17));
		expanded_key->k[23] = BSWAP_64(ROTR_128_LOW(kl, 17));

		break;
	}
}

camellia_key *new_camellia_key(camellia_type type, byte_t *key)
{
	camellia_key *expanded_key = NULL;

	if (type != CAMELLIA128 && type != CAMELLIA192 && type != CAMELLIA256)
	{
		return NULL;
	}

	expanded_key = (camellia_key *)malloc(sizeof(camellia_key));

	if (key == NULL)
	{
		return NULL;
	}

	expanded_key->type = type;
	camellia_key_expansion(expanded_key, key);

	return expanded_key;
}

void delete_camellia_key(camellia_key *key)
{
	// Zero the key for security reasons.
	memset(key, 0, sizeof(camellia_key));
	free(key);
}

void camellia_encrypt_block(camellia_key *key, byte_t plaintext[CAMELLIA_BLOCK_SIZE], byte_t ciphertext[CAMELLIA_BLOCK_SIZE])
{
	switch (key->type)
	{
	case CAMELLIA128:
		return camellia128_encrypt_block(key, plaintext, ciphertext);
	case CAMELLIA192:
	case CAMELLIA256:
		return camellia256_encrypt_block(key, plaintext, ciphertext);
	}
}

void camellia_decrypt_block(camellia_key *key, byte_t ciphertext[CAMELLIA_BLOCK_SIZE], byte_t plaintext[CAMELLIA_BLOCK_SIZE])
{
	switch (key->type)
	{
	case CAMELLIA128:
		return camellia128_decrypt_block(key, ciphertext, plaintext);
	case CAMELLIA192:
	case CAMELLIA256:
		return camellia256_decrypt_block(key, ciphertext, plaintext);
	}
}
