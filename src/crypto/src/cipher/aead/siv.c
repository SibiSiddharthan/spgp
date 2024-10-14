/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <types.h>
#include <cmac.h>
#include <byteswap.h>

#include "double-block.h"

// Refer RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption Using AES

static void s2v(cmac_ctx *cctx, byte_t iv[16], void *associated_data, size_t ad_size, void *plaintext, size_t plaintext_size)
{
	byte_t zero[16] = {0};
	byte_t buffer[16];
	byte_t dbl[16];

	uint64_t *b = (uint64_t *)buffer;
	uint64_t *d = (uint64_t *)dbl;

	// First block
	cmac_update(cctx, zero, 16);
	cmac_final(cctx, buffer, 16);
	cmac_reset(cctx, NULL, 0);

	double_block(dbl, buffer);

	// Associated data
	cmac_update(cctx, associated_data, ad_size);
	cmac_final(cctx, buffer, 16);
	cmac_reset(cctx, NULL, 0);

	b[0] ^= d[0];
	b[1] ^= d[1];

	double_block(dbl, buffer);

	// Plaintext
	if (plaintext_size >= 16)
	{
		cmac_update(cctx, associated_data, plaintext_size - 16);

		memcpy(buffer, (byte_t *)plaintext + (plaintext_size - 16), 16);

		b[0] ^= d[0];
		b[1] ^= d[1];

		cmac_update(cctx, buffer, 16);
		cmac_final(cctx, iv, 16);
	}
	else
	{
		memset(buffer, 0, 16);
		memcpy(buffer, plaintext, plaintext_size);

		b[0] ^= d[0];
		b[1] ^= d[1];

		cmac_update(cctx, buffer, 16);
		cmac_final(cctx, iv, 16);
	}
}

static void siv_ctr_encrypt(void (*encrypt)(void *key, void *plaintext, void *ciphertext), void *key, byte_t iv[16], void *plaintext,
							void *ciphertext, size_t size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = 16;

	byte_t buffer[16];

	byte_t *pin = (byte_t *)plaintext;
	byte_t *pout = (byte_t *)ciphertext;
	uint64_t *oc = (uint64_t *)&buffer[8];

	memcpy(buffer, iv, 16);

	uint64_t counter = BSWAP_64(*oc);

	while (processed + block_size <= size)
	{
		encrypt(key, buffer, buffer);

		for (uint8_t i = 0; i < block_size; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		++counter;
		*oc = BSWAP_64(counter);

		processed += block_size;
	}

	remaining = size - processed;

	encrypt(key, buffer, buffer);

	for (uint8_t i = 0; i < remaining; ++i)
	{
		pout[processed + i] = pin[processed + i] ^ buffer[i];
	}
}

uint32_t siv_cmac_ae(void (*encrypt)(void *key, void *plaintext, void *ciphertext), void *key, size_t key_size, uint32_t algorithm,
					 void *associated_data, size_t ad_size, void *plaintext, size_t plaintext_size, void *ciphertext,
					 size_t ciphertext_size)
{
	cmac_ctx *cctx = NULL;
	byte_t buffer[1024] = {0};

	byte_t iv[16];
	byte_t cmac_key[32];
	byte_t encrypt_key[32];

	if (key_size != 32 && key_size != 48 && key_size != 64)
	{
		return 0;
	}

	if (ciphertext_size < plaintext_size + 16)
	{
		return 0;
	}

	memcpy(cmac_key, key, key_size / 2);
	memcpy(encrypt_key, (byte_t *)key + (key_size / 2), key_size / 2);

	cctx = cmac_init(buffer, 1024, algorithm, cmac_key, key_size / 2);

	if (cctx == NULL)
	{
		return 0;
	}

	s2v(cctx, iv, associated_data, ad_size, plaintext, plaintext_size);
	siv_ctr_encrypt(encrypt, encrypt_key, iv, plaintext, (byte_t *)ciphertext + 16, plaintext_size);

	memcpy(ciphertext, iv, 16);

	return plaintext_size + 16;
}

uint32_t siv_cmac_ad(void (*encrypt)(void *key, void *plaintext, void *ciphertext), void *key, size_t key_size, uint32_t algorithm,
					 void *associated_data, size_t ad_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
					 size_t plaintext_size)
{
	cmac_ctx *cctx = NULL;
	byte_t buffer[1024] = {0};

	byte_t expected_iv[16];
	byte_t actual_iv[16];
	byte_t cmac_key[32];
	byte_t encrypt_key[32];

	if (key_size != 32 && key_size != 48 && key_size != 64)
	{
		return 0;
	}

	if (plaintext_size < ciphertext_size - 16)
	{
		return 0;
	}

	memcpy(cmac_key, key, key_size / 2);
	memcpy(encrypt_key, (byte_t *)key + (key_size / 2), key_size / 2);

	memcpy(actual_iv, ciphertext, 16);

	cctx = cmac_init(buffer, 1024, algorithm, cmac_key, key_size / 2);

	if (cctx == NULL)
	{
		return 0;
	}

	s2v(cctx, expected_iv, associated_data, ad_size, plaintext, plaintext_size);

	if (memcmp(actual_iv, expected_iv, 16) != 0)
	{
		return 0;
	}

	siv_ctr_encrypt(encrypt, encrypt_key, actual_iv, (byte_t *)ciphertext + 16, plaintext, ciphertext_size - 16);

	return ciphertext_size - 16;
}
