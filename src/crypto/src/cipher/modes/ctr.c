/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <byteswap.h>
#include <round.h>
#include <xor.h>

static inline uint64_t cipher_ctr_update_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;
	uint64_t *oc = (uint64_t *)&cctx->buffer[8];

	uint64_t counter = BSWAP_64(*oc);
	byte_t temp[16] = {0};

	while ((processed + block_size) <= size)
	{
		cctx->_encrypt(cctx->_ctx, cctx->buffer, temp);
		XOR8_N(pout + processed, pin + processed, temp, block_size);

		++counter;
		*oc = BSWAP_64(counter);

		processed += block_size;
	}

	remaining = size - processed;

	if (remaining > 0)
	{
		cctx->_encrypt(cctx->_ctx, cctx->buffer, temp);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ temp[i];
		}

		processed += remaining;
	}

	return processed;
}

static cipher_ctx *cipher_ctr_init_common(cipher_ctx *cctx, void *iv, size_t iv_size)
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

cipher_ctx *cipher_ctr_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	return cipher_ctr_init_common(cctx, iv, iv_size);
}

uint64_t cipher_ctr_encrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_ctr_update_core(cctx, in, out, ROUND_DOWN(in_size, cctx->block_size));
}

uint64_t cipher_ctr_encrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_ctr_update_core(cctx, in, out, in_size);
}

uint64_t cipher_ctr_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *plaintext, size_t plaintext_size, void *ciphertext,
							size_t ciphertext_size)
{
	cctx = cipher_ctr_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ctr_encrypt_final(cctx, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

cipher_ctx *cipher_ctr_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	return cipher_ctr_init_common(cctx, iv, iv_size);
}

uint64_t cipher_ctr_decrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_ctr_update_core(cctx, in, out, ROUND_DOWN(in_size, cctx->block_size));
}

uint64_t cipher_ctr_decrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_ctr_update_core(cctx, in, out, in_size);
}

uint64_t cipher_ctr_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *ciphertext, size_t ciphertext_size, void *plaintext,
							size_t plaintext_size)
{
	cctx = cipher_ctr_decrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ctr_decrypt_final(cctx, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

static uint64_t ctr_common(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size,
						   void *out, size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	if (out_size < in_size)
	{
		return 0;
	}

	cctx = cipher_init(buffer, 512, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_ctr_init_common(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ctr_update_core(cctx, in, out, in_size);
}

uint64_t aes128_ctr_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ctr_common(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes128_ctr_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ctr_common(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_ctr_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ctr_common(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_ctr_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ctr_common(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_ctr_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ctr_common(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_ctr_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return ctr_common(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}
