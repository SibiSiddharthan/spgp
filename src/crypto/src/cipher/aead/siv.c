/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <cipher.h>
#include <cmac.h>
#include <xor.h>

#include <stdlib.h>
#include <string.h>

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

		XOR16(dbl, dbl, buffer);
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

static uint64_t siv_cmac_ctr_update(cipher_ctx *cctx, byte_t iv[16], void *in, void *out, size_t size)
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

uint32_t cipher_siv_cmac_init(cipher_algorithm algorithm, void *key, size_t key_size, void *ci_ctx, size_t cipher_ctx_size, void *cm_ctx,
							  size_t cmac_ctx_size)
{
	if (key_size != 32 && key_size != 48 && key_size != 64)
	{
		return -1u;
	}

	if (ci_ctx == NULL || cm_ctx == NULL)
	{
		return -1u;
	}

	// First half of the key is the cmac key. Second half is the encryption key.
	cm_ctx = cmac_init(cm_ctx, cipher_ctx_size, algorithm, key, key_size / 2);
	ci_ctx = cipher_init(ci_ctx, cmac_ctx_size, 0, algorithm, PTR_OFFSET(key, key_size / 2), key_size / 2);

	if (ci_ctx == NULL || cm_ctx == NULL)
	{
		return -1u;
	}

	if (((cipher_ctx *)ci_ctx)->block_size != 16)
	{
		return -1u;
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
	siv_cmac_ctr_update(ci_ctx, iv, plaintext, PTR_OFFSET(ciphertext, 16), plaintext_size);

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

	siv_cmac_ctr_update(ci_ctx, actual_iv, PTR_OFFSET(ciphertext, 16), plaintext, plaintext_size);
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

// Refer RFC 8452: AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption

static inline void polyval_multiplication(uint64_t x[2], uint64_t y[2])
{
	const byte_t r[16] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC2};
	uint64_t z[2], v[2];

	// X = X * Y

	z[0] = 0;
	z[1] = 0;

	v[0] = x[0];
	v[1] = x[1];

	for (uint8_t i = 0; i < 128; ++i)
	{
		if (y[i / 64] & (1ull << (i % 64)))
		{
			XOR16(z, z, v);
		}

		if (v[1] & 0x8000000000000000)
		{
			v[1] = (v[1] << 1) | (v[0] >> 63);
			v[0] = v[0] << 1;

			XOR16(v, v, r);
		}
		else
		{
			v[1] = (v[1] << 1) | (v[0] >> 63);
			v[0] = v[0] << 1;
		}
	}

	x[0] = z[0];
	x[1] = z[1];
}

static void polyval(void *tag, void *authentication_key, void *associated_data, size_t ad_size, void *plaintext, size_t plaintext_size)
{
	const byte_t w[16] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x92};
	const uint16_t block_size = 16;

	byte_t buffer[16];
	uint64_t length[2];
	uint64_t hx128[2] = {0};

	uint64_t processed = 0;
	uint64_t remaining = 0;

	// Calculate H*(x^-128)
	memcpy(hx128, authentication_key, 16);
	polyval_multiplication(hx128, (uint64_t *)w);

	// Associated data
	while ((processed + block_size) <= ad_size)
	{
		XOR16(tag, tag, PTR_OFFSET(associated_data, processed));
		polyval_multiplication(tag, hx128);

		processed += 16;
	}

	remaining = ad_size - processed;

	if (remaining > 0)
	{
		memset(buffer, 0, 16);
		memcpy(buffer, PTR_OFFSET(associated_data, processed), remaining);

		XOR16(tag, tag, buffer);
		polyval_multiplication(tag, hx128);
	}

	processed = 0;

	// Plaintext
	while ((processed + block_size) <= plaintext_size)
	{
		XOR16(tag, tag, PTR_OFFSET(plaintext, processed));
		polyval_multiplication(tag, hx128);

		processed += 16;
	}

	remaining = plaintext_size - processed;

	if (remaining > 0)
	{
		memset(buffer, 0, 16);
		memcpy(buffer, PTR_OFFSET(plaintext, processed), remaining);

		XOR16(tag, tag, buffer);
		polyval_multiplication(tag, hx128);
	}

	// Length block
	length[0] = ad_size * 8;
	length[1] = plaintext_size * 8;

	XOR16(tag, tag, length);
	polyval_multiplication(tag, hx128);
}

static uint64_t siv_gcm_ctr_update(cipher_ctx *cctx, byte_t iv[16], void *in, void *out, size_t size)
{
	const uint16_t block_size = 16;

	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t buffer[16] = {0};
	byte_t icb[16] = {0};

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;
	uint32_t *oc = (uint32_t *)&icb[0];

	memcpy(icb, iv, 16);
	icb[15] |= 0x80;

	while ((processed + block_size) <= size)
	{
		cctx->_encrypt(cctx->_key, icb, buffer);
		XOR16(pout + processed, pin + processed, buffer);

		(*oc)++;
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

static byte_t cipher_siv_gcm_derive_keys(cipher_algorithm algorithm, void *key, size_t key_size, byte_t nonce[12],
										 byte_t authentication_key[16], byte_t encryption_key[32])
{
	cipher_ctx *cctx = NULL;
	byte_t cipher_buffer[512];

	byte_t buffer[16] = {0};
	byte_t block[16] = {0};
	uint32_t *oc = (uint32_t *)&block[0];

	cctx = cipher_init(cipher_buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	memcpy(block + 4, nonce, 12);

	// Authentication key
	*oc = 0;
	cctx->_encrypt(cctx->_key, block, buffer);
	memcpy(authentication_key, buffer, 8);

	*oc = 1;
	cctx->_encrypt(cctx->_key, block, buffer);
	memcpy(authentication_key + 8, buffer, 8);

	// Encryption key
	*oc = 2;
	cctx->_encrypt(cctx->_key, block, buffer);
	memcpy(encryption_key, buffer, 8);

	*oc = 3;
	cctx->_encrypt(cctx->_key, block, buffer);
	memcpy(encryption_key + 8, buffer, 8);

	if (key_size == 32)
	{
		*oc = 4;
		cctx->_encrypt(cctx->_key, block, buffer);
		memcpy(encryption_key + 16, buffer, 8);

		*oc = 5;
		cctx->_encrypt(cctx->_key, block, buffer);
		memcpy(encryption_key + 24, buffer, 8);
	}

	return (((*oc) - 1) * 8);
}

uint64_t cipher_siv_gcm_encrypt(cipher_algorithm algorithm, void *key, size_t key_size, void *nonce, byte_t nonce_size,
								void *associated_data, size_t ad_size, void *plaintext, size_t plaintext_size, void *ciphertext,
								size_t ciphertext_size)
{
	cipher_ctx *cctx = NULL;
	byte_t cipher_buffer[512];

	byte_t authentication_key[16] = {0};
	byte_t encryption_key[32] = {0};
	byte_t nonce_copy[16] = {0};
	byte_t tag[16] = {0};
	byte_t encryption_key_size = 0;

	if (key_size != 16 && key_size != 32)
	{
		return 0;
	}

	if (nonce_size != 12)
	{
		return 0;
	}

	if (ciphertext_size < (plaintext_size + 16))
	{
		return 0;
	}

	memcpy(nonce_copy, nonce, 12);

	encryption_key_size = cipher_siv_gcm_derive_keys(algorithm, key, key_size, nonce_copy, authentication_key, encryption_key);

	if (encryption_key_size == 0)
	{
		return 0;
	}

	cctx = cipher_init(cipher_buffer, 512, CIPHER_AEAD_INIT, algorithm, encryption_key, encryption_key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	polyval(tag, authentication_key, associated_data, ad_size, plaintext, plaintext_size);

	XOR16(tag, tag, nonce_copy);
	tag[15] &= 0x7F;

	cctx->_encrypt(cctx->_key, tag, tag);

	siv_gcm_ctr_update(cctx, tag, plaintext, ciphertext, plaintext_size);

	memcpy(PTR_OFFSET(ciphertext, plaintext_size), tag, 16);

	return plaintext_size + 16;
}

uint64_t cipher_siv_gcm_decrypt(cipher_algorithm algorithm, void *key, size_t key_size, void *nonce, byte_t nonce_size,
								void *associated_data, size_t ad_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
								size_t plaintext_size)
{
	cipher_ctx *cctx = NULL;
	byte_t cipher_buffer[512];

	byte_t authentication_key[16] = {0};
	byte_t encryption_key[32] = {0};
	byte_t nonce_copy[16] = {0};
	byte_t expected_tag[16] = {0};
	byte_t actual_tag[16] = {0};
	byte_t encryption_key_size = 0;

	if (key_size != 16 && key_size != 32)
	{
		return 0;
	}

	if (nonce_size != 12)
	{
		return 0;
	}

	if (ciphertext_size < 16)
	{
		return 0;
	}

	if (plaintext_size < (ciphertext_size - 16))
	{
		return 0;
	}

	plaintext_size = ciphertext_size - 16;

	memcpy(nonce_copy, nonce, 12);

	encryption_key_size = cipher_siv_gcm_derive_keys(algorithm, key, key_size, nonce_copy, authentication_key, encryption_key);

	if (encryption_key_size == 0)
	{
		return 0;
	}

	cctx = cipher_init(cipher_buffer, 512, CIPHER_AEAD_INIT, algorithm, encryption_key, encryption_key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	memcpy(expected_tag, PTR_OFFSET(ciphertext, ciphertext_size - 16), 16);

	siv_gcm_ctr_update(cctx, expected_tag, ciphertext, plaintext, plaintext_size);
	polyval(actual_tag, authentication_key, associated_data, ad_size, plaintext, plaintext_size);

	XOR16(actual_tag, actual_tag, nonce_copy);
	actual_tag[15] &= 0x7F;

	cctx->_encrypt(cctx->_key, actual_tag, actual_tag);

	if (memcmp(actual_tag, expected_tag, 16) != 0)
	{
		return 0;
	}

	return plaintext_size;
}

uint64_t aes128_siv_gcm_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
								size_t in_size, void *out, size_t out_size)
{
	return cipher_siv_gcm_encrypt(CIPHER_AES128, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size);
}

uint64_t aes128_siv_gcm_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
								size_t in_size, void *out, size_t out_size)
{
	return cipher_siv_gcm_decrypt(CIPHER_AES128, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size);
}

uint64_t aes256_siv_gcm_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
								size_t in_size, void *out, size_t out_size)
{
	return cipher_siv_gcm_encrypt(CIPHER_AES256, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size);
}

uint64_t aes256_siv_gcm_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
								size_t in_size, void *out, size_t out_size)
{
	return cipher_siv_gcm_decrypt(CIPHER_AES256, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size);
}
