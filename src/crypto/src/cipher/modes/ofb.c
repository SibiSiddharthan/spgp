/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <round.h>
#include <xor.h>

static inline uint64_t cipher_ofb_update_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	while ((processed + block_size) <= size)
	{
		cctx->_encrypt(cctx->_ctx, cctx->buffer, cctx->buffer);
		XOR8_N(pout + processed, pin + processed, cctx->buffer, block_size);

		processed += block_size;
	}

	remaining = size - processed;

	if (remaining > 0)
	{
		cctx->_encrypt(cctx->_ctx, cctx->buffer, cctx->buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ cctx->buffer[i];
		}

		processed += remaining;
	}

	return processed;
}

cipher_ctx *cipher_ofb_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
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

uint64_t cipher_ofb_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	if (ciphertext_size < plaintext_size)
	{
		return 0;
	}

	return cipher_ofb_update_core(cctx, plaintext, ciphertext, ROUND_DOWN(plaintext_size, cctx->block_size));
}

uint64_t cipher_ofb_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	if (ciphertext_size < plaintext_size)
	{
		return 0;
	}

	return cipher_ofb_update_core(cctx, plaintext, ciphertext, plaintext_size);
}

uint64_t cipher_ofb_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size)
{
	cctx = cipher_ofb_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ofb_encrypt_final(cctx, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

cipher_ctx *cipher_ofb_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
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

uint64_t cipher_ofb_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	return cipher_ofb_update_core(cctx, ciphertext, plaintext, ROUND_DOWN(ciphertext_size, cctx->block_size));
}

uint64_t cipher_ofb_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	return cipher_ofb_update_core(cctx, ciphertext, plaintext, ciphertext_size);
}

uint64_t cipher_ofb_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size)
{
	cctx = cipher_ofb_decrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ofb_decrypt_final(cctx, ciphertext, ciphertext_size, plaintext, plaintext_size);
}
