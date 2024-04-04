/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <chacha20.h>
#include <rotate.h>

static const uint32_t CHACHA20_CONSTANTS[4] = {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};

#define QUARTER_ROUND(A, B, C, D) \
	{                             \
		A += B;                   \
		D ^= A;                   \
		D = ROTL_32(D, 16);       \
		C += D;                   \
		B ^= C;                   \
		B = ROTL_32(B, 12);       \
		A += B;                   \
		D ^= A;                   \
		D = ROTL_32(D, 18);       \
		C += D;                   \
		B ^= C;                   \
		B = ROTL_32(B, 17);       \
	}

#define CHACHA20_STEP(S)                         \
	{                                            \
		/* Column Rounds */                      \
		QUARTER_ROUND(S[0], S[4], S[8], S[12]);  \
		QUARTER_ROUND(S[1], S[5], S[9], S[13]);  \
		QUARTER_ROUND(S[2], S[6], S[10], S[14]); \
		QUARTER_ROUND(S[3], S[7], S[11], S[15]); \
		/* Diagonal Rounds */                    \
		QUARTER_ROUND(S[0], S[5], S[10], S[15]); \
		QUARTER_ROUND(S[1], S[6], S[11], S[12]); \
		QUARTER_ROUND(S[2], S[7], S[8], S[13]);  \
		QUARTER_ROUND(S[3], S[4], S[9], S[14]);  \
	}

static inline void chacha20_block(uint32_t block[16])
{
	// Rounds 1 - 20 (Each step is 2 rounds)
	CHACHA20_STEP(block);
	CHACHA20_STEP(block);
	CHACHA20_STEP(block);
	CHACHA20_STEP(block);
	CHACHA20_STEP(block);
	CHACHA20_STEP(block);
	CHACHA20_STEP(block);
	CHACHA20_STEP(block);
	CHACHA20_STEP(block);
	CHACHA20_STEP(block);
}

chacha20_key *new_chacha20_key(byte_t *key, byte_t *nonce)
{
	chacha20_key *chacha_key = (chacha20_key *)malloc(sizeof(chacha20_key));

	if (chacha_key == NULL)
	{
		return NULL;
	}

	// First 4 32-bit words are the constants
	memcpy(chacha_key->constants, CHACHA20_CONSTANTS, sizeof(uint32_t) * 4);

	// Next 8 32-bit words is the 256 bit key
	memcpy(chacha_key->key, key, 32);

	// Standard count start value
	chacha_key->count = 1;

	// Last 3 32-bit words are the nonce
	memcpy(chacha_key->nonce, nonce, 12);

	return chacha_key;
}

void delete_chacha20_key(chacha20_key *key)
{
	// Zero the key for security reasons.
	memset(key, 0, sizeof(chacha20_key));
	free(key);
}

void chacha20_encrypt(chacha20_key *key, byte_t *plaintext, byte_t *ciphertext, size_t size)
{
	uint32_t block[16];
	uint32_t *in = (uint32_t *)plaintext;
	uint32_t *out = (uint32_t *)ciphertext;
	uint64_t processed = 0;

	for (processed = 0; processed + 64 <= size; processed += 64)
	{
		memcpy(block, key, sizeof(chacha20_key));
		key->count++;

		chacha20_block(block);

		*out++ = *in++ ^ block[0];
		*out++ = *in++ ^ block[1];
		*out++ = *in++ ^ block[2];
		*out++ = *in++ ^ block[3];
		*out++ = *in++ ^ block[4];
		*out++ = *in++ ^ block[5];
		*out++ = *in++ ^ block[6];
		*out++ = *in++ ^ block[7];
		*out++ = *in++ ^ block[8];
		*out++ = *in++ ^ block[9];
		*out++ = *in++ ^ block[10];
		*out++ = *in++ ^ block[11];
		*out++ = *in++ ^ block[12];
		*out++ = *in++ ^ block[13];
		*out++ = *in++ ^ block[14];
		*out++ = *in++ ^ block[15];
	}

	// Remaining byte
	if (processed < size)
	{
		uint32_t i = 0;
		memcpy(block, key, sizeof(chacha20_key));
		key->count++;

		chacha20_block(block);

		while (processed + 4 <= size)
		{
			*out++ = *in++ ^ block[i++];
		}

		// Last bytes
		switch (size - processed)
		{
		case 3:
			ciphertext[size - 3] = plaintext[size - 3] ^ ((block[i] >> 16) & 0xFF);
			// Fallthrough
		case 2:
			ciphertext[size - 2] = plaintext[size - 2] ^ ((block[i] >> 8) & 0xFF);
			// Fallthrough
		case 1:
			ciphertext[size - 1] = plaintext[size - 1] ^ (block[i] & 0xFF);
			// Fallthrough
		case 0:
			// All bytes processed
			break;
		}
	}
}

void chacha20_decrypt(chacha20_key *key, byte_t *ciphertext, byte_t *plaintext, size_t size)
{
		uint32_t block[16];
	uint32_t *in = (uint32_t *)ciphertext;
	uint32_t *out = (uint32_t *)plaintext;
	uint64_t processed = 0;

	for (processed = 0; processed + 64 <= size; processed += 64)
	{
		memcpy(block, key, sizeof(chacha20_key));
		key->count++;

		chacha20_block(block);

		*out++ = *in++ ^ block[0];
		*out++ = *in++ ^ block[1];
		*out++ = *in++ ^ block[2];
		*out++ = *in++ ^ block[3];
		*out++ = *in++ ^ block[4];
		*out++ = *in++ ^ block[5];
		*out++ = *in++ ^ block[6];
		*out++ = *in++ ^ block[7];
		*out++ = *in++ ^ block[8];
		*out++ = *in++ ^ block[9];
		*out++ = *in++ ^ block[10];
		*out++ = *in++ ^ block[11];
		*out++ = *in++ ^ block[12];
		*out++ = *in++ ^ block[13];
		*out++ = *in++ ^ block[14];
		*out++ = *in++ ^ block[15];
	}

	// Remaining byte
	if (processed < size)
	{
		uint32_t i = 0;
		memcpy(block, key, sizeof(chacha20_key));
		key->count++;

		chacha20_block(block);

		while (processed + 4 <= size)
		{
			*out++ = *in++ ^ block[i++];
		}

		// Last bytes
		switch (size - processed)
		{
		case 3:
			ciphertext[size - 3] = plaintext[size - 3] ^ ((block[i] >> 16) & 0xFF);
			// Fallthrough
		case 2:
			ciphertext[size - 2] = plaintext[size - 2] ^ ((block[i] >> 8) & 0xFF);
			// Fallthrough
		case 1:
			ciphertext[size - 1] = plaintext[size - 1] ^ (block[i] & 0xFF);
			// Fallthrough
		case 0:
			// All bytes processed
			break;
		}
	}
}
