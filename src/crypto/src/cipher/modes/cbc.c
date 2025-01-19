/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <round.h>
#include <xor.h>

#include "padding.h"

static inline uint64_t cipher_cbc_encrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	while ((processed + block_size) <= size)
	{
		XOR8_N(cctx->buffer, cctx->buffer, pin + processed, block_size);
		cctx->_encrypt(cctx->_key, cctx->buffer, cctx->buffer);

		memcpy(pout + processed, cctx->buffer, cctx->block_size);
		processed += block_size;
	}

	return processed;
}

static inline uint64_t cipher_cbc_decrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	while ((processed + block_size) <= size)
	{
		cctx->_decrypt(cctx->_key, pin + processed, temp);
		XOR8_N(pout + processed, cctx->buffer, temp, block_size);

		memcpy(cctx->buffer, pin + processed, block_size);
		processed += block_size;
	}

	return processed;
}

cipher_ctx *cipher_cbc_encrypt_init(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size)
{
	if (padding != PADDING_NONE && padding != PADDING_ZERO && padding != PADDING_ISO7816 && padding != PADDING_PKCS7)
	{
		return NULL;
	}

	if (cctx->algorithm == CIPHER_CHACHA20)
	{
		return NULL;
	}

	if (iv_size != cctx->block_size)
	{
		return NULL;
	}

	cctx->padding = padding;
	memcpy(cctx->buffer, iv, iv_size);

	return cctx;
}

uint64_t cipher_cbc_encrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cbc_encrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cbc_encrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[32] = {0};
	uint64_t required_size = 0;

	if (cctx->padding == PADDING_PKCS7)
	{
		required_size = ROUND_UP(in_size + 1, block_size);
	}
	else
	{
		required_size = ROUND_UP(in_size, block_size);
	}

	if (cctx->padding == PADDING_NONE)
	{
		if (in_size % block_size != 0)
		{
			return 0;
		}
	}

	if (out_size < required_size)
	{
		return 0;
	}

	// Process upto the last block
	processed += cipher_cbc_encrypt_core(cctx, in, out, in_size);
	remaining = in_size - processed;

	// Copy the remaining data to the buffer.
	memcpy(temp, pin + processed, remaining);
	fill_padding_block(cctx->padding, temp, block_size, remaining);

	if (cctx->padding == PADDING_PKCS7 || remaining > 0)
	{
		processed += cipher_cbc_encrypt_core(cctx, temp, pout + processed, block_size);
	}

	// Zero the internal buffer.
	memset(cctx->buffer, 0, block_size);

	return processed;
}

uint64_t cipher_cbc_encrypt(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size, void *in, size_t in_size, void *out,
							size_t out_size)
{
	cctx = cipher_cbc_encrypt_init(cctx, padding, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cbc_encrypt_final(cctx, in, in_size, out, out_size);
}

cipher_ctx *cipher_cbc_decrypt_init(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size)
{
	if (padding != PADDING_NONE && padding != PADDING_ZERO && padding != PADDING_ISO7816 && padding != PADDING_PKCS7)
	{
		return NULL;
	}

	if (cctx->algorithm == CIPHER_CHACHA20)
	{
		return NULL;
	}

	if (iv_size != cctx->block_size)
	{
		return NULL;
	}

	cctx->padding = padding;
	memcpy(cctx->buffer, iv, iv_size);

	return cctx;
}

uint64_t cipher_cbc_decrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cbc_decrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cbc_decrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[32] = {0};

	if (in_size % block_size != 0)
	{
		return 0;
	}

	if (out_size < in_size)
	{
		return 0;
	}

	// Process upto the last block.
	processed += cipher_cbc_decrypt_core(cctx, in, out, in_size - block_size);

	// Decrypt the last block to the internal buffer.
	cipher_cbc_decrypt_core(cctx, pin + processed, temp, block_size);

	// Get the remaining bytes to copy.
	remaining += check_for_padding(cctx->padding, temp, block_size);

	memcpy(pout + processed, temp, remaining);
	processed += remaining;

	// Zero the internal buffer.
	memset(cctx->buffer, 0, block_size);

	return processed;
}

uint64_t cipher_cbc_decrypt(cipher_ctx *cctx, cipher_padding padding, void *iv, size_t iv_size, void *in, size_t in_size, void *out,
							size_t out_size)
{
	cctx = cipher_cbc_decrypt_init(cctx, padding, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cbc_decrypt_final(cctx, in, in_size, out, out_size);
}

static uint64_t cbc_encrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in,
								   size_t in_size, void *out, size_t out_size, cipher_padding padding)
{
	// A big enough buffer for the hmac_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_cbc_encrypt_init(cctx, padding, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cbc_encrypt_final(cctx, in, in_size, out, out_size);
}

static uint64_t cbc_decrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in,
								   size_t in_size, void *out, size_t out_size, cipher_padding padding)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_cbc_decrypt_init(cctx, padding, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cbc_decrypt_final(cctx, in, in_size, out, out_size);
}

uint64_t aes128_cbc_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size,
							cipher_padding padding)
{
	return cbc_encrypt_common(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size, padding);
}

uint64_t aes128_cbc_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size,
							cipher_padding padding)
{
	return cbc_decrypt_common(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size, padding);
}

uint64_t aes192_cbc_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size,
							cipher_padding padding)
{
	return cbc_encrypt_common(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size, padding);
}

uint64_t aes192_cbc_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size,
							cipher_padding padding)
{
	return cbc_decrypt_common(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size, padding);
}

uint64_t aes256_cbc_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size,
							cipher_padding padding)
{
	return cbc_encrypt_common(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size, padding);
}

uint64_t aes256_cbc_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size,
							cipher_padding padding)
{
	return cbc_decrypt_common(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size, padding);
}
