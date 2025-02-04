/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <cipher.h>
#include <xor.h>

#include <string.h>

static inline uint64_t cipher_ofb_update_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	while ((processed + block_size) <= size)
	{
		cctx->_encrypt(cctx->_key, cctx->buffer, cctx->buffer);
		XOR8_N(pout + processed, pin + processed, cctx->buffer, block_size);

		processed += block_size;
	}

	remaining = size - processed;

	if (remaining > 0)
	{
		cctx->_encrypt(cctx->_key, cctx->buffer, cctx->buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ cctx->buffer[i];
		}

		processed += remaining;
	}

	return processed;
}

static cipher_ctx *cipher_ofb_init_common(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	if (cctx->algorithm == CIPHER_CHACHA20)
	{
		return NULL;
	}

	if (iv_size != cctx->block_size)
	{
		return NULL;
	}

	memcpy(cctx->buffer, iv, iv_size);

	return cctx;
}

cipher_ctx *cipher_ofb_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	return cipher_ofb_init_common(cctx, iv, iv_size);
}

uint64_t cipher_ofb_encrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_ofb_update_core(cctx, in, out, ROUND_DOWN(in_size, cctx->block_size));
}

uint64_t cipher_ofb_encrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_ofb_update_core(cctx, in, out, in_size);
}

uint64_t cipher_ofb_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_ofb_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ofb_encrypt_final(cctx, in, in_size, out, out_size);
}

cipher_ctx *cipher_ofb_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	return cipher_ofb_init_common(cctx, iv, iv_size);
}

uint64_t cipher_ofb_decrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_ofb_update_core(cctx, in, out, ROUND_DOWN(in_size, cctx->block_size));
}

uint64_t cipher_ofb_decrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_ofb_update_core(cctx, in, out, in_size);
}

uint64_t cipher_ofb_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_ofb_decrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ofb_decrypt_final(cctx, in, in_size, out, out_size);
}

static uint64_t ofb_common(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size,
						   void *out, size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	if (out_size < in_size)
	{
		return 0;
	}

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_ofb_init_common(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ofb_update_core(cctx, in, out, in_size);
}

uint64_t aes128_ofb_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ofb_common(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes128_ofb_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ofb_common(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_ofb_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ofb_common(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_ofb_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ofb_common(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_ofb_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ofb_common(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_ofb_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ofb_common(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}
