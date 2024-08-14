/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <round.h>

static inline void SHL128_1(byte_t buffer[16], byte_t bit)
{
	uint64_t *t1 = (uint64_t *)&buffer[0];
	uint64_t *t2 = (uint64_t *)&buffer[8];

	*t1 = (*t1 >> 1 | ((*t2 & 0x1) << 63));
	*t2 = (*t2 >> 1 | ((uint64_t)bit << 63));
}

static inline void SHL128_8(byte_t buffer[16], byte_t byte)
{
	uint64_t *t1 = (uint64_t *)&buffer[0];
	uint64_t *t2 = (uint64_t *)&buffer[8];

	*t1 = (*t1 >> 8 | ((*t2 & 0x1) << 56));
	*t2 = (*t2 >> 8 | ((uint64_t)byte << 56));
}

static inline void SHL128_64(byte_t buffer[16], uint64_t qword)
{
	uint64_t *t1 = (uint64_t *)&buffer[0];
	uint64_t *t2 = (uint64_t *)&buffer[8];

	*t1 = *t2;
	*t2 = qword;
}

static inline byte_t get_bit(byte_t b, uint8_t i)
{
	return (b >> (7 - i)) & 0x1;
}

uint64_t cipher_cfb1_update_common(cipher_ctx *cctx, void (*cipher_ops)(void *, void *, void *), void *in, size_t in_size, void *out,
								   size_t out_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	if (in_size < out_size)
	{
		return 0;
	}

	while (processed < in_size)
	{
		byte_t out = 0;

		for (uint8_t i = 0; i < 8; ++i)
		{
			cipher_ops(cctx->_ctx, cctx->buffer, cctx->buffer);
			out |= (get_bit(pin[processed], i) << (7 - i)) ^ (get_bit(cctx->buffer[0], i) << (7 - i));
			SHL128_1(cctx->buffer, get_bit(out, i));
		}

		pout[processed] = out;

		++result;
		++processed;
	}

	return result;
}

uint64_t cipher_cfb8_update_common(cipher_ctx *cctx, void (*cipher_ops)(void *, void *, void *), void *in, size_t in_size, void *out,
								   size_t out_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	if (in_size < out_size)
	{
		return 0;
	}

	while (processed < in_size)
	{
		cipher_ops(cctx->_ctx, cctx->buffer, cctx->buffer);
		pout[processed] = pin[processed] ^ cctx->buffer[0];
		SHL128_8(cctx->buffer, pout[processed]);

		++result;
		++processed;
	}

	return result;
}

uint64_t cipher_cfb64_update_common(cipher_ctx *cctx, void (*cipher_ops)(void *, void *, void *), void *in, size_t in_size, void *out,
									size_t out_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	if (in_size % 8 != 0)
	{
		return 0;
	}

	if (in_size < out_size)
	{
		return 0;
	}

	while (processed < in_size)
	{
		uint64_t *ip = (uint64_t *)&pin[processed];
		uint64_t *op = (uint64_t *)&pout[processed];
		uint64_t *bp = (uint64_t *)cctx->buffer;

		cipher_ops(cctx->_ctx, cctx->buffer, cctx->buffer);
		op[0] = ip[0] ^ bp[0];
		SHL128_64(cctx->buffer, op[0]);

		result += 8;
		processed += 8;
	}

	return result;
}

uint64_t cipher_cfb128_update_common(cipher_ctx *cctx, void (*cipher_ops)(void *, void *, void *), void *in, size_t in_size, void *out,
									 size_t out_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	if (in_size % 16 != 0)
	{
		return 0;
	}

	if (in_size < out_size)
	{
		return 0;
	}

	while (processed < in_size)
	{
		uint64_t *ip = (uint64_t *)&pin[processed];
		uint64_t *op = (uint64_t *)&pout[processed];
		uint64_t *bp = (uint64_t *)cctx->buffer;

		cipher_ops(cctx->_ctx, cctx->buffer, cctx->buffer);
		op[0] = ip[0] ^ bp[0];
		op[1] = ip[1] ^ bp[1];
		memcpy(op, cctx->buffer, 16);

		result += 16;
		processed += 16;
	}

	return result;
}

uint64_t cipher_cfb1_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return cipher_cfb1_update_common(cctx, cctx->_encrypt_block, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint64_t cipher_cfb1_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return cipher_cfb1_update_common(cctx, cctx->_encrypt_block, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

uint64_t cipher_cfb1_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return cipher_cfb1_update_common(cctx, cctx->_encrypt_block, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint64_t cipher_cfb1_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return cipher_cfb1_update_common(cctx, cctx->_encrypt_block, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

uint64_t cipher_cfb8_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return cipher_cfb8_update_common(cctx, cctx->_encrypt_block, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint64_t cipher_cfb8_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return cipher_cfb8_update_common(cctx, cctx->_encrypt_block, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

uint64_t cipher_cfb8_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return cipher_cfb8_update_common(cctx, cctx->_encrypt_block, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint64_t cipher_cfb8_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return cipher_cfb8_update_common(cctx, cctx->_encrypt_block, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

uint64_t cipher_cfb64_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return cipher_cfb64_update_common(cctx, cctx->_encrypt_block, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint64_t cipher_cfb64_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return cipher_cfb64_update_common(cctx, cctx->_encrypt_block, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

uint64_t cipher_cfb128_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return cipher_cfb128_update_common(cctx, cctx->_encrypt_block, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint64_t cipher_cfb128_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return cipher_cfb128_update_common(cctx, cctx->_encrypt_block, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

uint64_t cipher_cfb64_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = 8;

	byte_t *pin = (byte_t *)plaintext;
	byte_t *pout = (byte_t *)ciphertext;
	byte_t last_block[16] = {0};

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
		uint64_t *ip = (uint64_t *)&pin[processed];
		uint64_t *op = (uint64_t *)&pout[processed];
		uint64_t *bp = (uint64_t *)cctx->buffer;

		cctx->_encrypt_block(cctx->_ctx, cctx->buffer, cctx->buffer);
		op[0] = ip[0] ^ bp[0];
		SHL128_64(cctx->buffer, op[0]);

		result += block_size;
		processed += block_size;
	}

	remaining = plaintext_size - processed;

	if (remaining == 0)
	{
		if (cctx->padding == PADDING_PKCS7)
		{
			cctx->_encrypt_block(cctx->_ctx, cctx->buffer, cctx->buffer);

			for (uint8_t i = 0; i < block_size; ++i)
			{
				pout[result++] ^= block_size;
			}
		}

		return result;
	}

	// Copy the remaining data to the buffer.
	memcpy(last_block, pin + processed, remaining);

	switch (cctx->padding)
	{
	case PADDING_ZERO:
		break;

	case PADDING_ISO7816:
		last_block[remaining] = 0x80;
		break;

	case PADDING_PKCS7:
		memset(last_block + remaining, block_size - remaining, block_size - remaining);
		break;
	}

	cctx->_encrypt_block(cctx->_ctx, cctx->buffer, pout + result);

	for (uint8_t i = 0; i < block_size; ++i)
	{
		pout[result++] ^= last_block[i];
	}

	return result;
}

uint64_t cipher_cfb64_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint16_t block_size = 8;

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
	while (processed + block_size <= ciphertext_size)
	{
		uint64_t *ip = (uint64_t *)&pin[processed];
		uint64_t *op = (uint64_t *)&pout[processed];
		uint64_t *bp = (uint64_t *)cctx->buffer;

		cctx->_encrypt_block(cctx->_ctx, cctx->buffer, cctx->buffer);
		op[0] = ip[0] ^ bp[0];
		SHL128_64(cctx->buffer, op[0]);

		result += block_size;
		processed += block_size;
	}

	// Decrypt the last block
	cctx->_encrypt_block(cctx->_ctx, cctx->buffer, cctx->buffer);

	for (uint8_t i = 0; i < block_size; ++i)
	{
		cctx->buffer[i] ^= *(pin + processed + i);
	}

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

uint64_t cipher_cfb128_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint64_t remaining = 0;
	uint16_t block_size = 16;

	byte_t *pin = (byte_t *)plaintext;
	byte_t *pout = (byte_t *)ciphertext;
	byte_t last_block[16] = {0};

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
		uint64_t *ip = (uint64_t *)&pin[processed];
		uint64_t *op = (uint64_t *)&pout[processed];
		uint64_t *bp = (uint64_t *)cctx->buffer;

		cctx->_encrypt_block(cctx->_ctx, cctx->buffer, cctx->buffer);
		op[0] = ip[0] ^ bp[0];
		op[1] = ip[1] ^ bp[1];
		memcpy(op, cctx->buffer, block_size);

		result += block_size;
		processed += block_size;
	}

	remaining = plaintext_size - processed;

	if (remaining == 0)
	{
		if (cctx->padding == PADDING_PKCS7)
		{
			cctx->_encrypt_block(cctx->_ctx, cctx->buffer, cctx->buffer);

			for (uint8_t i = 0; i < block_size; ++i)
			{
				pout[result++] ^= block_size;
			}
		}

		return result;
	}

	// Copy the remaining data to the buffer.
	memcpy(last_block, pin + processed, remaining);

	switch (cctx->padding)
	{
	case PADDING_ZERO:
		break;

	case PADDING_ISO7816:
		last_block[remaining] = 0x80;
		break;

	case PADDING_PKCS7:
		memset(last_block + remaining, block_size - remaining, block_size - remaining);
		break;
	}

	cctx->_encrypt_block(cctx->_ctx, cctx->buffer, pout + result);

	for (uint8_t i = 0; i < block_size; ++i)
	{
		pout[result++] ^= last_block[i];
	}

	return result;
}

uint64_t cipher_cfb128_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;
	uint64_t processed = 0;
	uint16_t block_size = 16;

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
	while (processed + block_size <= ciphertext_size)
	{
		uint64_t *ip = (uint64_t *)&pin[processed];
		uint64_t *op = (uint64_t *)&pout[processed];
		uint64_t *bp = (uint64_t *)cctx->buffer;

		cctx->_encrypt_block(cctx->_ctx, cctx->buffer, cctx->buffer);
		op[0] = ip[0] ^ bp[0];
		op[1] = ip[1] ^ bp[1];
		memcpy(op, cctx->buffer, block_size);

		result += block_size;
		processed += block_size;
	}

	// Decrypt the last block
	cctx->_encrypt_block(cctx->_ctx, cctx->buffer, cctx->buffer);

	for (uint8_t i = 0; i < block_size; ++i)
	{
		cctx->buffer[i] ^= *(pin + processed + i);
	}

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
