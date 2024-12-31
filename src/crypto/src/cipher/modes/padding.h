/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CIPHER_PADDING_H
#define CRYPTO_CIPHER_PADDING_H

#include <string.h>
#include <cipher.h>

static inline void fill_padding_block(cipher_padding padding, byte_t *block, uint16_t block_size, uint16_t offset)
{
	if (offset == 0)
	{
		memset(block, block_size, block_size);
	}
	else
	{
		if (padding == PADDING_ZERO)
		{
			memset(block + offset, 0, block_size - offset);
		}
		else if (padding == PADDING_ISO7816)
		{
			block[offset] = 0x80;
			memset(block + offset + 1, 0, block_size - (offset + 1));
		}
		else if (padding == PADDING_PKCS7)
		{
			memset(block + offset, block_size - offset, block_size - offset);
		}
	}
}

static uint16_t check_padding_pkcs7(byte_t *block, uint16_t block_size)
{
	byte_t last_byte = block[block_size - 1];
	uint8_t count = 0;

	for (uint8_t i = 0; i < last_byte; ++i)
	{
		if (block[block_size - 1 - i] == last_byte)
		{
			++count;
		}
	}

	if (count == last_byte)
	{
		if (last_byte == block_size)
		{
			// Empty last block.
			return 0;
		}

		return block_size - count;
	}

	return block_size;
}

static int32_t check_padding_iso7816(byte_t *block, uint16_t block_size)
{
	uint8_t count = 0;

	if (block[block_size - 1] == 0)
	{
		for (uint16_t i = 0; i < block_size; ++i)
		{
			count += block[block_size - 1 - i];

			if (count != 0 && count == 0x80)
			{
				return block_size - i - 1;
			}
		}
	}

	return block_size;
}

static uint16_t check_padding_zero(byte_t *block, uint16_t block_size)
{
	uint8_t count = 0;

	if (block[block_size - 1] == 0)
	{
		for (uint16_t i = 0; i < block_size; ++i)
		{
			count += block[block_size - 1 - i];

			if (count != 0)
			{
				return block_size - i;
			}
		}
	}

	return block_size;
}

static uint16_t check_for_padding(cipher_padding padding, byte_t *block, uint16_t block_size)
{
	if (padding == PADDING_PKCS7)
	{
		return check_padding_pkcs7(block, block_size);
	}
	else if (padding == PADDING_ISO7816)
	{
		return check_padding_zero(block, block_size);
	}
	else if (padding == PADDING_ZERO)
	{
		return check_padding_iso7816(block, block_size);
	}

	return block_size;
}

#endif
