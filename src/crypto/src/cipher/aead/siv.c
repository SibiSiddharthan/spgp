/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <cmac.h>

#include <byteswap.h>
#include <ptr.h>
#include <xor.h>

#include "double-block.h"

// Refer RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption Using AES

static void s2v(cmac_ctx *cctx, byte_t iv[16], void **associated_data, size_t *ad_size, uint32_t ad_count, void *nonce, size_t nonce_size,
				void *plaintext, size_t plaintext_size)
{
	byte_t zero[16] = {0};
	byte_t buffer[16];
	byte_t dbl[16];

	// First block
	cmac_update(cctx, zero, 16);
	cmac_final(cctx, buffer, 16);
	cmac_reset(cctx, NULL, 0);

	double_block(dbl, buffer);

	// Associated data
	for (uint32_t i = 0; i < ad_count; ++i)
	{
		cmac_update(cctx, associated_data[i], ad_size[i]);
		cmac_final(cctx, buffer, 16);
		cmac_reset(cctx, NULL, 0);

		XOR16(buffer, buffer, dbl);
		double_block(dbl, buffer);
	}

	// Optional Nonce
	if (nonce != NULL && nonce_size > 0)
	{
		cmac_update(cctx, nonce, nonce_size);
		cmac_final(cctx, buffer, 16);
		cmac_reset(cctx, NULL, 0);

		XOR16(buffer, buffer, dbl);
		double_block(dbl, buffer);
	}

	// Plaintext
	if (plaintext_size >= 16)
	{
		cmac_update(cctx, plaintext, plaintext_size - 16);

		memcpy(buffer, PTR_OFFSET(plaintext, (plaintext_size - 16)), 16);
		XOR16(buffer, buffer, dbl);

		cmac_update(cctx, buffer, 16);
		cmac_final(cctx, iv, 16);
	}
	else
	{
		memset(buffer, 0, 16);
		memcpy(buffer, plaintext, plaintext_size);

		buffer[plaintext_size] = 0x80;

		XOR16(buffer, buffer, dbl);

		cmac_update(cctx, buffer, 16);
		cmac_final(cctx, iv, 16);
	}
}

static uint64_t siv_ctr_update(cipher_ctx *cctx, byte_t iv[16], void *in, void *out, size_t size)
{
	const uint16_t block_size = 16;
	const uint64_t mask = ((1ull << 63) - 1) - (1ull << 31); // Zero 63, 31 bit

	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t buffer[16] = {0};
	byte_t icb[16] = {0};

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;
	uint64_t *oc = (uint64_t *)&icb[8];
	uint64_t counter = 0;

	memcpy(icb, iv, 16);
	counter = BSWAP_64(*oc);

	// Initial mask
	counter &= mask;
	*oc = BSWAP_64(counter);

	while ((processed + block_size) <= size)
	{
		cctx->_encrypt(cctx->_key, icb, buffer);

		XOR16(pout + processed, pin + processed, buffer);

		for (uint8_t i = 0; i < block_size; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		counter &= mask;
		counter += 1;
		*oc = BSWAP_64(counter);

		processed += block_size;
	}

	remaining = size - processed;

	if (remaining > 0)
	{

		cctx->_encrypt(cctx->_key, icb, buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		processed += block_size;
	}

	return processed;
}

int32_t cipher_siv_cmac_init(cipher_algorithm algorithm, void *key, size_t key_size, void *ci_ctx, size_t cipher_ctx_size, void *cm_ctx,
							 size_t cmac_ctx_size)
{
	if (key_size != 32 && key_size != 48 && key_size != 64)
	{
		return -1;
	}

	if (ci_ctx == NULL || cm_ctx == NULL)
	{
		return -1;
	}

	// First half of the key is the cmac key. Second half is the encryption key.
	cm_ctx = cmac_init(cm_ctx, cipher_ctx_size, algorithm, key, key_size / 2);
	ci_ctx = cipher_init(ci_ctx, cmac_ctx_size, algorithm, PTR_OFFSET(key, key_size / 2), key_size / 2);

	if (ci_ctx == NULL || cm_ctx == NULL)
	{
		return -1;
	}

	if (((cipher_ctx *)ci_ctx)->block_size != 16)
	{
		return -1;
	}

	return 0;
}

uint64_t cipher_siv_cmac_encrypt(cipher_ctx *ci_ctx, cmac_ctx *cm_ctx, void **associated_data, size_t *ad_size, uint32_t ad_count,
								 void *nonce, size_t nonce_size, void *plaintext, size_t plaintext_size, void *ciphertext,
								 size_t ciphertext_size)
{
	byte_t iv[16] = {0};

	if (ciphertext_size < (plaintext_size + 16))
	{
		return 0;
	}

	s2v(cm_ctx, iv, associated_data, ad_size, ad_count, nonce, nonce_size, plaintext, plaintext_size);
	siv_ctr_update(ci_ctx, iv, plaintext, PTR_OFFSET(ciphertext, 16), plaintext_size);

	memcpy(ciphertext, iv, 16);

	return plaintext_size + 16;
}

uint64_t cipher_siv_cmac_decrypt(cipher_ctx *ci_ctx, cmac_ctx *cm_ctx, void **associated_data, size_t *ad_size, uint32_t ad_count,
								 void *nonce, size_t nonce_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
								 size_t plaintext_size)
{
	byte_t expected_iv[16] = {0};
	byte_t actual_iv[16] = {0};

	if (plaintext_size < (ciphertext_size - 16))
	{
		return 0;
	}

	plaintext_size = ciphertext_size - 16;

	memcpy(actual_iv, ciphertext, 16);

	siv_ctr_update(ci_ctx, actual_iv, PTR_OFFSET(ciphertext, 16), plaintext, plaintext_size);
	s2v(cm_ctx, expected_iv, associated_data, ad_size, ad_count, nonce, nonce_size, plaintext, plaintext_size);

	if (memcmp(actual_iv, expected_iv, 16) != 0)
	{
		return 0;
	}

	return plaintext_size;
}

static uint64_t siv_encrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void **associated_data, size_t *ad_size,
								   uint32_t ad_count, void *nonce, size_t nonce_size, void *in, size_t in_size, void *out, size_t out_size)
{
	byte_t cipher_buffer[512];
	byte_t cmac_buffer[512];

	cipher_ctx *ci_ctx = (cipher_ctx *)cipher_buffer;
	cmac_ctx *cm_ctx = (cmac_ctx *)cmac_buffer;

	if (cipher_siv_cmac_init(algorithm, key, key_size, ci_ctx, 512, cm_ctx, 512) != 0)
	{
		return 0;
	}

	return cipher_siv_cmac_encrypt(ci_ctx, cm_ctx, associated_data, ad_size, ad_count, nonce, nonce_size, in, in_size, out, out_size);
}

static uint64_t siv_decrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void **associated_data, size_t *ad_size,
								   uint32_t ad_count, void *nonce, size_t nonce_size, void *in, size_t in_size, void *out, size_t out_size)
{
	byte_t cipher_buffer[512];
	byte_t cmac_buffer[512];

	cipher_ctx *ci_ctx = (cipher_ctx *)cipher_buffer;
	cmac_ctx *cm_ctx = (cmac_ctx *)cmac_buffer;

	if (cipher_siv_cmac_init(algorithm, key, key_size, ci_ctx, 512, cm_ctx, 512) != 0)
	{
		return 0;
	}

	return cipher_siv_cmac_decrypt(ci_ctx, cm_ctx, associated_data, ad_size, ad_count, nonce, nonce_size, in, in_size, out, out_size);
}

uint64_t aes256_siv_cmac_encrypt(void *key, size_t key_size, void **associated_data, size_t *ad_size, uint32_t ad_count, void *nonce,
								 size_t nonce_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return siv_encrypt_common(CIPHER_AES128, key, key_size, associated_data, ad_size, ad_count, nonce, nonce_size, in, in_size, out,
							  out_size);
}

uint64_t aes256_siv_cmac_decrypt(void *key, size_t key_size, void **associated_data, size_t *ad_size, uint32_t ad_count, void *nonce,
								 size_t nonce_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return siv_decrypt_common(CIPHER_AES128, key, key_size, associated_data, ad_size, ad_count, nonce, nonce_size, in, in_size, out,
							  out_size);
}

uint64_t aes384_siv_cmac_encrypt(void *key, size_t key_size, void **associated_data, size_t *ad_size, uint32_t ad_count, void *nonce,
								 size_t nonce_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return siv_encrypt_common(CIPHER_AES192, key, key_size, associated_data, ad_size, ad_count, nonce, nonce_size, in, in_size, out,
							  out_size);
}

uint64_t aes384_siv_cmac_decrypt(void *key, size_t key_size, void **associated_data, size_t *ad_size, uint32_t ad_count, void *nonce,
								 size_t nonce_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return siv_decrypt_common(CIPHER_AES192, key, key_size, associated_data, ad_size, ad_count, nonce, nonce_size, in, in_size, out,
							  out_size);
}

uint64_t aes512_siv_cmac_encrypt(void *key, size_t key_size, void **associated_data, size_t *ad_size, uint32_t ad_count, void *nonce,
								 size_t nonce_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return siv_encrypt_common(CIPHER_AES256, key, key_size, associated_data, ad_size, ad_count, nonce, nonce_size, in, in_size, out,
							  out_size);
}

uint64_t aes512_siv_cmac_decrypt(void *key, size_t key_size, void **associated_data, size_t *ad_size, uint32_t ad_count, void *nonce,
								 size_t nonce_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return siv_decrypt_common(CIPHER_AES256, key, key_size, associated_data, ad_size, ad_count, nonce, nonce_size, in, in_size, out,
							  out_size);
}
