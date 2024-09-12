/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <round.h>
#include <byteswap.h>

uint64_t cipher_ctr_update_common(cipher_ctx *cctx, void (*cipher_ops)(void *, void *, void *), void *in, size_t in_size, void *out,
								  size_t out_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;
	uint64_t *oc = (uint64_t *)&cctx->buffer[8];

	uint64_t counter = BSWAP_64(*oc);

	// Make sure input is a multiple of block_size
	if (in_size % block_size != 0)
	{
		return 0;
	}

	if (in_size < out_size)
	{
		return 0;
	}

	while (processed < in_size)
	{
		cipher_ops(cctx->_ctx, cctx->buffer, cctx->buffer);

		for (uint8_t i = 0; i < block_size; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ cctx->buffer[i];
		}

		++counter;
		*oc = BSWAP_64(counter);

		result += block_size;
		processed += block_size;
	}

	return result;
}

uint64_t cipher_ctr_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return cipher_ctr_update_common(cctx, cctx->_encrypt, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint64_t cipher_ctr_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return cipher_ctr_update_common(cctx, cctx->_encrypt, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

uint64_t cipher_ctr_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)plaintext;
	byte_t *pout = (byte_t *)ciphertext;
	uint64_t *oc = (uint64_t *)&cctx->buffer[8];

	uint64_t counter = BSWAP_64(*oc);

	if (ciphertext_size < plaintext_size)
	{
		return 0;
	}

	while (processed + block_size <= plaintext_size)
	{
		cctx->_encrypt(cctx->_ctx, cctx->buffer, cctx->buffer);

		for (uint8_t i = 0; i < block_size; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ cctx->buffer[i];
		}

		++counter;
		*oc = BSWAP_64(counter);

		result += block_size;
		processed += block_size;
	}

	remaining = plaintext_size - processed;

	cctx->_encrypt(cctx->_ctx, cctx->buffer, cctx->buffer);

	for (uint8_t i = 0; i < remaining; ++i)
	{
		pout[processed + i] = pin[processed + i] ^ cctx->buffer[i];
	}

	result += remaining;

	return result;
}

uint64_t cipher_ctr_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)ciphertext;
	byte_t *pout = (byte_t *)plaintext;
	uint64_t *oc = (uint64_t *)&cctx->buffer[8];

	uint64_t counter = BSWAP_64(*oc);

	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	// Process upto the last block.
	while (processed + block_size <= ciphertext_size)
	{
		cctx->_encrypt(cctx->_ctx, cctx->buffer, cctx->buffer);

		for (uint8_t i = 0; i < block_size; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ cctx->buffer[i];
		}

		++counter;
		*oc = BSWAP_64(counter);

		result += block_size;
		processed += block_size;
	}

	remaining = ciphertext_size - processed;

	// Decrypt the last block
	cctx->_encrypt(cctx->_ctx, cctx->buffer, cctx->buffer);

	for (uint8_t i = 0; i < remaining; ++i)
	{
		cctx->buffer[i] ^= *(pin + processed + i);
	}

	result += remaining;

	return result;
}
