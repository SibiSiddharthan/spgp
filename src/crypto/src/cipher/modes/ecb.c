/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <round.h>

uint64_t cipher_ecb_update_common(cipher_ctx *cctx, void (*cipher_ops)(void *, void *, void *), void *in, size_t in_size, void *out,
								  size_t out_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

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
		cipher_ops(cctx->_ctx, pin + processed, pout + result);

		result += block_size;
		processed += block_size;
	}

	return result;
}

uint64_t cipher_ecb_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return cipher_ecb_update_common(cctx, cctx->_encrypt_block, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint64_t cipher_ecb_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return cipher_ecb_update_common(cctx, cctx->_decrypt_block, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

uint64_t cipher_ecb_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)plaintext;
	byte_t *pout = (byte_t *)ciphertext;

	uint64_t required_size = 0;

	if (cctx->padding == PADDING_PKCS7)
	{
		required_size = ROUND_UP(plaintext_size + 1, block_size);
	}
	else
	{
		required_size = ROUND_UP(plaintext_size, block_size);
	}

	if (required_size < ciphertext_size)
	{
		return 0;
	}

	while (processed + block_size <= plaintext_size)
	{
		cctx->_encrypt_block(cctx->_ctx, pin + processed, pout + result);

		result += block_size;
		processed += block_size;
	}

	remaining = plaintext_size - processed;

	if (remaining == 0)
	{
		if (cctx->padding == PADDING_PKCS7)
		{
			// Fill the last block with 'block_size' bytes.
			memset(cctx->buffer, block_size, block_size);
			cctx->_encrypt_block(cctx->_ctx, cctx->buffer, pout + result);
			result += block_size;
		}

		return result;
	}

	// Copy the remaining data to the buffer.
	memcpy(cctx->buffer, pin + processed, remaining);

	switch (cctx->padding)
	{
	case PADDING_ZERO:
		memset(cctx->buffer + remaining, 0, block_size - remaining);
		break;

	case PADDING_ISO7816:
		cctx->buffer[remaining] = 0x80;
		memset(cctx->buffer + remaining + 1, 0, block_size - (remaining + 1));
		break;

	case PADDING_PKCS7:
		memset(cctx->buffer + remaining, block_size - remaining, block_size - remaining);
		break;
	}

	cctx->_encrypt_block(cctx->_ctx, cctx->buffer, pout + result);
	result += block_size;

	return result;
}

uint64_t cipher_ecb_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint16_t block_size = cctx->block_size;

	byte_t *pin = (byte_t *)ciphertext;
	byte_t *pout = (byte_t *)plaintext;

	byte_t *last_block = NULL;
	uint8_t last_byte = 0;
	uint8_t count = 0;

	if (plaintext_size % block_size != 0)
	{
		return 0;
	}

	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	// Process upto the last block.
	while (processed < (ciphertext_size - block_size))
	{
		cctx->_decrypt_block(cctx->_ctx, pin + processed, pout + result);

		result += block_size;
		processed += block_size;
	}

	// Decrypt the last block
	cctx->_decrypt_block(cctx->_ctx, pin + processed, cctx->buffer);

	// Check for PKCS7 padding
	last_block = cctx->buffer;
	last_byte = last_block[block_size - 1];
	count = 0;

	for (uint8_t i = 0; i < last_byte; ++i)
	{
		if (last_block[block_size - 1 - i] == last_byte)
		{
			++count;
		}
	}

	if (count == last_byte)
	{
		if (last_byte == block_size)
		{
			// Empty last block.
			return result;
		}

		memcpy(pout + result, last_block, block_size - count);
		result += (block_size - count);

		return result;
	}

	// Check for zero ending.
	count = 0;

	if (last_block[block_size - 1] == 0)
	{
		for (uint16_t i = 0; i < block_size; ++i)
		{
			count += last_block[block_size - 1 - i];

			if (count != 0)
			{
				if (count == 0x80)
				{
					// ISO-7816 padding
					memcpy(pout + result, last_block, block_size - 1 - i);
					result += (block_size - 1 - i);

					return result;
				}
				else
				{
					// Zero padding
					memcpy(pout + result, last_block, block_size - 1 - i);
					result += (block_size - 1 - i);

					return result;
				}
			}
		}
	}

	// Perfect block.
	memcpy(pout + result, cctx->buffer, block_size);
	result += block_size;

	return result;
}
