/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>
#include <round.h>
#include <xor.h>

// See NIST SP 800-38D Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC

static inline void block_multiplication(uint64_t x[2], uint64_t y[2])
{
	const byte_t R[16] = {0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	uint64_t *r = (uint64_t *)R;
	uint64_t z[2], v[2];

	z[0] = 0;
	z[1] = 0;

	v[0] = x[0];
	v[1] = x[1];

	for (uint8_t i = 0; i < 128; ++i)
	{
		byte_t a, b;

		if (y[i / 64] & (1ull << (7 - (i % 8) + (i / 8) * 8)))
		{
			z[0] ^= v[0];
			z[1] ^= v[1];
		}

		a = v[0] >> 56;
		b = v[1] >> 56;

		if (b & 0x1)
		{
			v[1] = (BSWAP_64(v[1]) >> 1) | ((a & 0x1) ? 0x8000000000000000 : 0);
			v[0] = BSWAP_64(v[0]) >> 1;

			v[0] = BSWAP_64(v[0]);
			v[1] = BSWAP_64(v[1]);

			v[0] ^= r[0];
		}
		else
		{
			v[1] = (BSWAP_64(v[1]) >> 1) | ((a & 0x1) ? 0x8000000000000000 : 0);
			v[0] = BSWAP_64(v[0]) >> 1;

			v[0] = BSWAP_64(v[0]);
			v[1] = BSWAP_64(v[1]);
		}
	}

	x[0] = z[0];
	x[1] = z[1];
}

void ghash(void *state, void *key, void *data, size_t size)
{

	uint64_t processed = 0;

	uint64_t *x = data;
	uint64_t *y = state;
	uint64_t *h = key;

	while (processed < size)
	{
		y[0] ^= x[0];
		y[1] ^= x[1];

		block_multiplication(y, h);

		// Move by 16 bytes.
		x += 2;
		processed += 16;
	}
}

uint64_t gctr_update(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	const uint16_t block_size = 16;

	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = in;
	byte_t *pout = out;

	uint32_t *pc = PTR_OFFSET(cctx->gcm.icb, 12);
	uint32_t counter = BSWAP_32(*pc);

	byte_t buffer[16];

	while ((processed + block_size) <= size)
	{
		cctx->_encrypt(cctx->_key, cctx->gcm.icb, buffer);
		XOR16(pout + processed, pin + processed, buffer);

		++counter;
		*pc = BSWAP_32(counter);

		processed += block_size;
	}

	remaining = size - processed;

	if (remaining > 0)
	{
		cctx->_encrypt(cctx->_key, cctx->gcm.icb, buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		processed += remaining;
	}

	return processed;
}

static cipher_ctx *cipher_gcm_init_common(cipher_ctx *cctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size)
{
	byte_t zero[16] = {0};
	byte_t buffer[16];

	// Check block size
	if (cctx->block_size != 16)
	{
		return NULL;
	}

	memset(&cctx->gcm, 0, sizeof(cctx->gcm));

	// Initialize H
	cctx->_encrypt(cctx->_key, zero, cctx->gcm.h);

	// Initialize J
	if (iv_size == 12)
	{
		memcpy(cctx->gcm.j, iv, 12);
		cctx->gcm.j[15] = 1;
	}
	else
	{
		size_t iv_rd_size = ROUND_DOWN(iv_size, 16);
		uint64_t *pb = (uint64_t *)buffer;

		ghash(cctx->gcm.j, cctx->gcm.h, iv, iv_rd_size);

		if (iv_rd_size < iv_size)
		{
			memset(buffer, 0, 16);
			memcpy(buffer, (byte_t *)iv + iv_rd_size, iv_size - iv_rd_size);
			ghash(cctx->gcm.j, cctx->gcm.h, buffer, 16);
		}

		pb[0] = 0;
		pb[1] = BSWAP_64(iv_size * 8);

		ghash(cctx->gcm.j, cctx->gcm.h, buffer, 16);
	}

	// Calculate ghash for associated data
	size_t ad_rd_size = ROUND_DOWN(ad_size, 16);

	ghash(cctx->gcm.s, cctx->gcm.h, associated_data, ad_rd_size);

	if (ad_rd_size < ad_size)
	{
		memset(buffer, 0, 16);
		memcpy(buffer, (byte_t *)associated_data + ad_rd_size, ad_size - ad_rd_size);
		ghash(cctx->gcm.s, cctx->gcm.h, buffer, 16);
	}

	cctx->gcm.ad_size = ad_size;

	// Set ICB
	uint32_t *counter = NULL;

	memcpy(cctx->gcm.icb, cctx->gcm.j, 16);
	counter = (uint32_t *)&cctx->gcm.icb[12];

	*counter = BSWAP_32(*counter);
	*counter += 1;
	*counter = BSWAP_32(*counter);

	return cctx;
}

cipher_ctx *cipher_gcm_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size)
{
	return cipher_gcm_init_common(cctx, iv, iv_size, associated_data, ad_size);
}

uint64_t cipher_gcm_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;

	if (ciphertext_size < plaintext_size)
	{
		return 0;
	}

	result = gctr_update(cctx, plaintext, ciphertext, ROUND_DOWN(plaintext_size, cctx->block_size));
	cctx->gcm.data_size += result;

	ghash(cctx->gcm.s, cctx->gcm.h, ciphertext, result);

	return result;
}

uint64_t cipher_gcm_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size,
								  void *tag, size_t tag_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t rd = 0;

	byte_t buffer[16] = {0};
	uint64_t *pb = (uint64_t *)buffer;

	if (ciphertext_size < plaintext_size)
	{
		return 0;
	}

	result = gctr_update(cctx, plaintext, ciphertext, plaintext_size);
	cctx->gcm.data_size += result;

	rd = ROUND_DOWN(result, 16);

	ghash(cctx->gcm.s, cctx->gcm.h, ciphertext, rd);

	if (rd < result)
	{
		memset(buffer, 0, block_size);
		memcpy(buffer, PTR_OFFSET(ciphertext, rd), result - rd);
		ghash(cctx->gcm.s, cctx->gcm.h, buffer, block_size);
	}

	pb[0] = BSWAP_64(cctx->gcm.ad_size * 8);
	pb[1] = BSWAP_64(cctx->gcm.data_size * 8);

	ghash(cctx->gcm.s, cctx->gcm.h, buffer, block_size);

	cctx->_encrypt(cctx->_key, cctx->gcm.j, cctx->gcm.j);
	XOR16(buffer, cctx->gcm.s, cctx->gcm.j);

	memcpy(tag, buffer, MIN(tag_size, 16));

	return result;
}

uint64_t cipher_gcm_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size, void *plaintext,
							size_t plaintext_size, void *ciphertext, size_t ciphertext_size, void *tag, size_t tag_size)
{
	cctx = cipher_gcm_init_common(cctx, iv, iv_size, associated_data, ad_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_gcm_encrypt_final(cctx, plaintext, plaintext_size, ciphertext, ciphertext_size, tag, tag_size);
}

cipher_ctx *cipher_gcm_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size)
{
	return cipher_gcm_init_common(cctx, iv, iv_size, associated_data, ad_size);
}

uint64_t cipher_gcm_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;

	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	result = gctr_update(cctx, ciphertext, plaintext, ROUND_DOWN(ciphertext_size, cctx->block_size));
	cctx->gcm.data_size += result;

	ghash(cctx->gcm.s, cctx->gcm.h, ciphertext, result);

	return result;
}

uint64_t cipher_gcm_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size,
								  void *tag, size_t tag_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t rd = 0;

	byte_t buffer[16] = {0};
	uint64_t *pb = (uint64_t *)buffer;

	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	result = gctr_update(cctx, ciphertext, plaintext, ciphertext_size);
	cctx->gcm.data_size += result;

	rd = ROUND_DOWN(result, 16);

	ghash(cctx->gcm.s, cctx->gcm.h, ciphertext, rd);

	if (rd < result)
	{
		memset(buffer, 0, block_size);
		memcpy(buffer, PTR_OFFSET(ciphertext, rd), result - rd);
		ghash(cctx->gcm.s, cctx->gcm.h, buffer, block_size);
	}

	pb[0] = BSWAP_64(cctx->gcm.ad_size * 8);
	pb[1] = BSWAP_64(cctx->gcm.data_size * 8);

	ghash(cctx->gcm.s, cctx->gcm.h, buffer, block_size);

	cctx->_encrypt(cctx->_key, cctx->gcm.j, cctx->gcm.j);
	XOR16(buffer, cctx->gcm.s, cctx->gcm.j);

	if (memcmp(tag, buffer, tag_size) != 0)
	{
		return 0;
	}

	return result;
}

uint64_t cipher_gcm_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *associated_data, size_t ad_size, void *ciphertext,
							size_t ciphertext_size, void *plaintext, size_t plaintext_size, void *tag, size_t tag_size)
{
	cctx = cipher_gcm_init_common(cctx, iv, iv_size, associated_data, ad_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_gcm_decrypt_final(cctx, ciphertext, ciphertext_size, plaintext, plaintext_size, tag, tag_size);
}

static uint64_t gcm_ecnrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, byte_t iv_size, void *associated_data,
								   size_t ad_size, void *in, size_t in_size, void *out, size_t out_size, void *tag, size_t tag_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_gcm_encrypt(cctx, iv, iv_size, associated_data, ad_size, in, in_size, out, out_size, tag, tag_size);
}

static uint64_t gcm_decrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, byte_t iv_size, void *associated_data,
								   size_t ad_size, void *in, size_t in_size, void *out, size_t out_size, void *tag, size_t tag_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_gcm_decrypt(cctx, iv, iv_size, associated_data, ad_size, in, in_size, out, out_size, tag, tag_size);
}

uint64_t aes128_gcm_encrypt(void *key, size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, size_t tag_size)
{
	return gcm_ecnrypt_common(CIPHER_AES128, key, key_size, iv, iv_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes128_gcm_decrypt(void *key, size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, size_t tag_size)
{
	return gcm_decrypt_common(CIPHER_AES128, key, key_size, iv, iv_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes192_gcm_encrypt(void *key, size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, size_t tag_size)
{
	return gcm_ecnrypt_common(CIPHER_AES192, key, key_size, iv, iv_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes192_gcm_decrypt(void *key, size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, size_t tag_size)
{
	return gcm_decrypt_common(CIPHER_AES192, key, key_size, iv, iv_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes256_gcm_encrypt(void *key, size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, size_t tag_size)
{
	return gcm_ecnrypt_common(CIPHER_AES256, key, key_size, iv, iv_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}
uint64_t aes256_gcm_decrypt(void *key, size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, size_t tag_size)
{
	return gcm_decrypt_common(CIPHER_AES256, key, key_size, iv, iv_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}
