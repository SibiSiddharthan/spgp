/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <twofish.h>
#include <rotate.h>

static const byte_t Q0[256] = {
	0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38, 0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7,
	0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59,
	0xF3, 0xAE, 0xA2, 0x82, 0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61, 0xC0, 0x8C,
	0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
	0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7, 0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9,
	0x62, 0x71, 0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 0xA1, 0x1D, 0xAA, 0xED,
	0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90, 0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C,
	0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF, 0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
	0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A, 0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C,
	0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D, 0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12,
	0x58, 0x07, 0x99, 0x34, 0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4, 0xCA, 0x10,
	0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0};

static const byte_t Q1[256] = {
	0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B, 0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71,
	0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E,
	0x80, 0x5D, 0xD2, 0xD5, 0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51, 0x38, 0xB0,
	0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
	0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8, 0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7,
	0x2B, 0xE2, 0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 0x66, 0x94, 0xA1, 0x1D,
	0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E, 0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88,
	0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9, 0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
	0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64, 0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7,
	0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69, 0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34,
	0x35, 0x6A, 0xCF, 0xDC, 0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9, 0xD7, 0x61,
	0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91};

#define XTIME(A)  (((A) & 0X80) ? (((A) << 1) ^ 0X69) : ((A) << 1))
#define X2TIME(A) (XTIME(XTIME((A))))
#define X3TIME(A) (X2TIME(XTIME((A))))
#define X4TIME(A) (X2TIME(X2TIME((A))))
#define X5TIME(A) (X3TIME(X2TIME((A))))
#define X6TIME(A) (X3TIME(X3TIME((A))))
#define X7TIME(A) (X4TIME(X3TIME((A))))

#define GF01TIME(A) (A)
#define GF02TIME(A) (XTIME(A))
#define GF03TIME(A) (XTIME(A) ^ (A))
#define GF19TIME(A) (X4TIME(A) ^ X3TIME(A) ^ (A))
#define GF1ETIME(A) (X4TIME(A) ^ X3TIME(A) ^ X2TIME(A) ^ XTIME(A))
#define GF3DTIME(A) (X5TIME(A) ^ X4TIME(A) ^ X3TIME(A) ^ X2TIME(A) ^ (A))
#define GF47TIME(A) (X6TIME(A) ^ X2TIME(A) ^ XTIME(A) ^ (A))
#define GF55TIME(A) (X6TIME(A) ^ X4TIME(A) ^ X2TIME(A) ^ (A))
#define GF56TIME(A) (X6TIME(A) ^ X4TIME(A) ^ X2TIME(A) ^ XTIME(A))
#define GF58TIME(A) (X6TIME(A) ^ X4TIME(A) ^ X3TIME(A))
#define GF5ATIME(A) (X6TIME(A) ^ X4TIME(A) ^ X3TIME(A) ^ XTIME(A))
#define GF5BTIME(A) (X6TIME(A) ^ X4TIME(A) ^ X3TIME(A) ^ XTIME(A) ^ (A))
#define GF68TIME(A) (X6TIME(A) ^ X5TIME(A) ^ X3TIME(A))
#define GF82TIME(A) (X7TIME(A) ^ XTIME(A))
#define GF87TIME(A) (X7TIME(A) ^ X2TIME(A) ^ XTIME(A) ^ (A))
#define GF9ETIME(A) (X7TIME(A) ^ X4TIME(A) ^ X3TIME(A) ^ X2TIME(A) ^ XTIME(A))
#define GFA1TIME(A) (X7TIME(A) ^ X5TIME(A) ^ (A))
#define GFA4TIME(A) (X7TIME(A) ^ X5TIME(A) ^ X2TIME(A))
#define GFAETIME(A) (X7TIME(A) ^ X5TIME(A) ^ X3TIME(A) ^ X2TIME(A) ^ XTIME(A))
#define GFC1TIME(A) (X7TIME(A) ^ X6TIME(A) ^ (A))
#define GFC6TIME(A) (X7TIME(A) ^ X6TIME(A) ^ X2TIME(A) ^ XTIME(A))
#define GFDBTIME(A) (X7TIME(A) ^ X6TIME(A) ^ X4TIME(A) ^ X4TIME(A) ^ XTIME(A) ^ (A))
#define GFE5TIME(A) (X7TIME(A) ^ X6TIME(A) ^ X5TIME(A) ^ X2TIME(A) ^ (A))
#define GFEFTIME(A) (X7TIME(A) ^ X6TIME(A) ^ X5TIME(A) ^ X3TIME(A) ^ X2TIME(A) ^ XTIME(A) ^ (A))
#define GFF3TIME(A) (X7TIME(A) ^ X6TIME(A) ^ X5TIME(A) ^ X4TIME(A) ^ XTIME(A) ^ (A))
#define GFFCTIME(A) (X7TIME(A) ^ X6TIME(A) ^ X5TIME(A) ^ X4TIME(A) ^ X3TIME(A) ^ X2TIME(A))

static uint32_t RS(uint64_t k)
{
	uint32_t o;
	byte_t *in = (byte_t *)&k;
	byte_t *out = (byte_t *)&o;

	out[0] = GF01TIME(in[0]) ^ GFA4TIME(in[1]) ^ GF55TIME(in[2]) ^ GF87TIME(in[3]) ^ GF5ATIME(in[4]) ^ GF58TIME(in[5]) ^ GFDBTIME(in[6]) ^
			 GF9ETIME(in[7]);
	out[1] = GFA4TIME(in[0]) ^ GF56TIME(in[1]) ^ GF82TIME(in[2]) ^ GFF3TIME(in[3]) ^ GF1ETIME(in[4]) ^ GFC6TIME(in[5]) ^ GF68TIME(in[6]) ^
			 GFE5TIME(in[7]);
	out[2] = GF02TIME(in[0]) ^ GFA1TIME(in[1]) ^ GFFCTIME(in[2]) ^ GFC1TIME(in[3]) ^ GF47TIME(in[4]) ^ GFAETIME(in[5]) ^ GF3DTIME(in[6]) ^
			 GF19TIME(in[7]);
	out[3] = GFA4TIME(in[0]) ^ GF55TIME(in[1]) ^ GF87TIME(in[2]) ^ GF5ATIME(in[3]) ^ GF58TIME(in[4]) ^ GFDBTIME(in[5]) ^ GF9ETIME(in[6]) ^
			 GF03TIME(in[7]);

	return o;
}

static inline uint32_t MDS(uint32_t k)
{
	uint32_t o;
	byte_t *in = (byte_t *)&k;
	byte_t *out = (byte_t *)&o;

	out[0] = GF01TIME(in[0]) ^ GFEFTIME(in[1]) ^ GF5BTIME(in[2]) ^ GF5BTIME(in[3]);
	out[1] = GF5BTIME(in[0]) ^ GFEFTIME(in[1]) ^ GFEFTIME(in[2]) ^ GF01TIME(in[3]);
	out[2] = GFEFTIME(in[0]) ^ GF5BTIME(in[1]) ^ GF01TIME(in[2]) ^ GFEFTIME(in[3]);
	out[3] = GFEFTIME(in[0]) ^ GF01TIME(in[1]) ^ GFEFTIME(in[2]) ^ GF5BTIME(in[3]);

	return o;
}

static uint32_t H(twofish_type type, uint32_t x, uint32_t s[4])
{
	byte_t *in = (byte_t *)&x;

	switch (type)
	{
	case TWOFISH256:
		in[0] = Q1[in[0]];
		in[1] = Q0[in[1]];
		in[2] = Q0[in[2]];
		in[3] = Q1[in[3]];
		x ^= s[3];
		// Fallthrough
	case TWOFISH192:
		in[0] = Q0[in[0]];
		in[1] = Q0[in[1]];
		in[2] = Q1[in[2]];
		in[3] = Q1[in[3]];
		x ^= s[2];
		// Fallthrough
	case TWOFISH128:
		in[0] = Q1[in[0]];
		in[1] = Q0[in[1]];
		in[2] = Q1[in[2]];
		in[3] = Q0[in[3]];
		x ^= s[1];

		in[0] = Q1[in[0]];
		in[1] = Q1[in[1]];
		in[2] = Q0[in[2]];
		in[3] = Q0[in[3]];
		x ^= s[0];
	}

	in[0] = Q0[in[0]];
	in[1] = Q1[in[1]];
	in[2] = Q0[in[2]];
	in[3] = Q1[in[3]];

	x = MDS(x);

	return x;
}

static inline uint32_t SBOX(twofish_key *key, uint32_t k)
{
	uint32_t o;
	byte_t *in = (byte_t *)&k;
	byte_t *out = (byte_t *)&o;

	out[0] = key->sbox0[in[0]];
	out[1] = key->sbox1[in[1]];
	out[2] = key->sbox2[in[2]];
	out[3] = key->sbox3[in[3]];

	return o;
}

#define G(KEY, X) MDS(SBOX(KEY, X))

#define TWOFISH_STEP(I, KEY, P, T)           \
	{                                        \
		T[0] = G(KEY, P[0]);                 \
		T[1] = G(KEY, ROTL_32(P[1], 8));     \
		/* PHT */                            \
		T[0] += T[1]; /* t0 = t0 + t1 */     \
		T[1] += T[0]; /* t1 = t0 + 2t1 */    \
                                             \
		/* Round keys */                     \
		T[0] += KEY->round_key[(2 * I) + 8]; \
		T[1] += KEY->round_key[(2 * I) + 9]; \
                                             \
		/* Shift, Swap */                    \
		T[2] = P[0];                         \
		T[3] = P[1];                         \
                                             \
		P[0] = ROTR_32((T[0] ^ P[2]), 1);    \
		P[1] = T[1] ^ ROTL_32(P[3], 1);      \
		P[2] = T[2];                         \
		P[3] = T[3];                         \
	}

static void twofish_key_expansion(twofish_key *expanded_key, byte_t *actual_key)
{
	uint32_t me[4], mo[4], ms[4];
	uint32_t *dword = (uint32_t *)actual_key;
	uint64_t *qword = (uint64_t *)actual_key;

	switch (expanded_key->type)
	{
	case TWOFISH128:
		me[0] = dword[0];
		me[1] = dword[2];

		mo[0] = dword[1];
		mo[1] = dword[3];

		ms[1] = RS(qword[0]);
		ms[0] = RS(qword[1]);

		break;
	case TWOFISH192:
		me[0] = dword[0];
		me[1] = dword[2];
		me[2] = dword[4];

		mo[0] = dword[1];
		mo[1] = dword[3];
		mo[2] = dword[5];

		ms[2] = RS(qword[0]);
		ms[1] = RS(qword[1]);
		ms[0] = RS(qword[2]);

		break;
	case TWOFISH256:
		me[0] = dword[0];
		me[1] = dword[2];
		me[2] = dword[4];
		me[3] = dword[6];

		mo[0] = dword[1];
		mo[1] = dword[3];
		mo[2] = dword[5];
		mo[3] = dword[7];

		ms[3] = RS(qword[0]);
		ms[2] = RS(qword[1]);
		ms[1] = RS(qword[2]);
		ms[0] = RS(qword[3]);

		break;
	}

	// Key dependent sboxes
	for (uint32_t i = 0; i < 256; ++i)
	{
		uint32_t x = (i << 24) + (i << 16) + (i << 8) + i;

		x = H(expanded_key->type, x, ms);

		expanded_key->sbox0[i] = x & 0xFF;
		expanded_key->sbox1[i] = (x >> 8) & 0xFF;
		expanded_key->sbox2[i] = (x >> 16) & 0xFF;
		expanded_key->sbox3[i] = (x >> 24) & 0xFF;
	}

	// Key expansion
	for (uint32_t i = 0; i < TWOFISH_ROUNDS + 4; ++i)
	{
		uint32_t x = 2 * i;
		uint32_t y = 2 * i + 1;
		uint32_t a = H(expanded_key->type, (x << 24) + (x << 16) + (x << 8) + x, me);
		uint32_t b = H(expanded_key->type, (y << 24) + (y << 16) + (y << 8) + y, mo);

		b = ROTL_32(b, 8);
		expanded_key->round_key[2 * i] = a + b;
		expanded_key->round_key[(2 * i) + 1] = ROTL_32(a + 2 * b, 9);
	}
}

twofish_key *new_twofish_key(twofish_type type, byte_t *key)
{
	twofish_key *expanded_key = NULL;

	if (type != TWOFISH128 && type != TWOFISH192 && type != TWOFISH256)
	{
		return NULL;
	}

	expanded_key = (twofish_key *)malloc(sizeof(twofish_key));

	if (expanded_key == NULL)
	{
		return NULL;
	}

	memset(expanded_key, 0, sizeof(twofish_key));

	expanded_key->type = type;
	twofish_key_expansion(expanded_key, key);

	return expanded_key;
}

void delete_twofish_key(twofish_key *key)
{
	// Zero the key for security reasons.
	memset(key, 0, sizeof(twofish_key));
	free(key);
}

void twofish_encrypt_block(twofish_key *key, byte_t plaintext[TWOFISH_BLOCK_SIZE], byte_t ciphertext[TWOFISH_BLOCK_SIZE])
{
	uint32_t p[4], t[4];
	uint32_t *dword;

	// Input whitening
	dword = (uint32_t *)plaintext;
	p[0] = dword[0] ^ key->round_key[0];
	p[1] = dword[1] ^ key->round_key[1];
	p[2] = dword[2] ^ key->round_key[2];
	p[3] = dword[3] ^ key->round_key[3];

	// Round 1 - 16
	TWOFISH_STEP(0, key, p, t);
	TWOFISH_STEP(1, key, p, t);
	TWOFISH_STEP(2, key, p, t);
	TWOFISH_STEP(3, key, p, t);
	TWOFISH_STEP(4, key, p, t);
	TWOFISH_STEP(5, key, p, t);
	TWOFISH_STEP(6, key, p, t);
	TWOFISH_STEP(7, key, p, t);
	TWOFISH_STEP(8, key, p, t);
	TWOFISH_STEP(9, key, p, t);
	TWOFISH_STEP(10, key, p, t);
	TWOFISH_STEP(11, key, p, t);
	TWOFISH_STEP(12, key, p, t);
	TWOFISH_STEP(13, key, p, t);
	TWOFISH_STEP(14, key, p, t);
	TWOFISH_STEP(15, key, p, t);

	// Output whitening
	dword = (uint32_t *)ciphertext;
	dword[0] = p[2] ^ key->round_key[4];
	dword[1] = p[3] ^ key->round_key[5];
	dword[2] = p[0] ^ key->round_key[6];
	dword[3] = p[1] ^ key->round_key[7];
}

void twofish_decrypt_block(twofish_key *key, byte_t ciphertext[TWOFISH_BLOCK_SIZE], byte_t plaintext[TWOFISH_BLOCK_SIZE])
{
	uint32_t p[4], t[4];
	uint32_t *dword;

	// Input whitening
	dword = (uint32_t *)ciphertext;
	p[0] = dword[0] ^ key->round_key[4];
	p[1] = dword[1] ^ key->round_key[5];
	p[2] = dword[2] ^ key->round_key[6];
	p[3] = dword[3] ^ key->round_key[7];

	// Round 1 - 16
	TWOFISH_STEP(15, key, p, t);
	TWOFISH_STEP(14, key, p, t);
	TWOFISH_STEP(13, key, p, t);
	TWOFISH_STEP(12, key, p, t);
	TWOFISH_STEP(11, key, p, t);
	TWOFISH_STEP(10, key, p, t);
	TWOFISH_STEP(9, key, p, t);
	TWOFISH_STEP(8, key, p, t);
	TWOFISH_STEP(7, key, p, t);
	TWOFISH_STEP(6, key, p, t);
	TWOFISH_STEP(5, key, p, t);
	TWOFISH_STEP(4, key, p, t);
	TWOFISH_STEP(3, key, p, t);
	TWOFISH_STEP(2, key, p, t);
	TWOFISH_STEP(1, key, p, t);
	TWOFISH_STEP(0, key, p, t);

	// Output whitening
	dword = (uint32_t *)plaintext;
	dword[0] = p[2] ^ key->round_key[0];
	dword[1] = p[3] ^ key->round_key[1];
	dword[2] = p[0] ^ key->round_key[2];
	dword[3] = p[1] ^ key->round_key[3];
}
