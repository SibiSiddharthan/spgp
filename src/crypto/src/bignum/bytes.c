/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include <bitscan.h>
#include <byteswap.h>
#include <minmax.h>
#include <round.h>

bignum_t *bignum_set_bytes_le(bignum_t *bn, byte_t *bytes, size_t size)
{
	if (bn == NULL)
	{
		bn = bignum_new(size * 8);

		if (bn == NULL)
		{
			return NULL;
		}
	}
	else
	{
		if (bn->size < size)
		{
			return NULL;
		}
	}

	// Just copy the bytes straight to the word buffer.
	memcpy(bn->words, bytes, size);

	// Update bitcount.
	bn->bits = bignum_bitcount(bn);

	return bn;
}

bignum_t *bignum_set_bytes_be(bignum_t *bn, byte_t *bytes, size_t size)
{
	uint64_t *word = (uint64_t *)bytes;
	size_t count = ROUND_UP(size, BIGNUM_WORD_SIZE) / BIGNUM_WORD_SIZE;
	int32_t pos = 0;

	if (bn == NULL)
	{
		bn = bignum_new(size * 8);

		if (bn == NULL)
		{
			return NULL;
		}
	}
	else
	{
		if (bn->size < size)
		{
			return NULL;
		}
	}

	// Copy 64-bit words at a time, BSWAP'd.
	for (size_t i = 0; i < count - 1; ++i)
	{
		bn->words[i] = BSWAP_64(word[count - i - 1]);
	}

	bn->words[count - 1] = 0;

	switch (size % 8)
	{
	case 0:
		bn->words[count - 1] = BSWAP_64(word[0]);
		break;
	case 7:
		bn->words[count - 1] = bytes[pos++];
		bn->words[count - 1] <<= 8;
		// Fallthrough
	case 6:
		bn->words[count - 1] += bytes[pos++];
		bn->words[count - 1] <<= 8;
		// Fallthrough
	case 5:
		bn->words[count - 1] += bytes[pos++];
		bn->words[count - 1] <<= 8;
		// Fallthrough
	case 4:
		bn->words[count - 1] += bytes[pos++];
		bn->words[count - 1] <<= 8;
		// Fallthrough
	case 3:
		bn->words[count - 1] += bytes[pos++];
		bn->words[count - 1] <<= 8;
		// Fallthrough
	case 2:
		bn->words[count - 1] += bytes[pos++];
		bn->words[count - 1] <<= 8;
		// Fallthrough
	case 1:
		bn->words[count - 1] += bytes[pos++];
	}

	// Update bitcount.
	bn->bits = bignum_bitcount(bn);

	return bn;
}

int32_t bignum_get_bytes_le(bignum_t *bn, byte_t *bytes, size_t size)
{
	size_t required_size = CEIL_DIV(bn->bits, 8);

	if (size < required_size)
	{
		return -1;
	}

	memcpy(bytes, bn->words, required_size);

	return 0;
}

int32_t bignum_get_bytes_be(bignum_t *bn, byte_t *bytes, size_t size)
{
	uint64_t *word = (uint64_t *)bytes;
	size_t count = ROUND_UP(bn->bits, BIGNUM_WORD_SIZE) / BIGNUM_WORD_SIZE;
	size_t required_size = CEIL_DIV(bn->bits, 8);

	if (required_size < size)
	{
		return -1;
	}

	for (size_t i = 0; i < count; ++i)
	{
		word[i] = BSWAP_64(bn->words[count - i - 1]);
	}

	return 0;
}

static const char nibble_to_hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

// clang-format off
static const byte_t hex_to_nibble_table[256] = 
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,                       // 0 - 9
	10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // A - F
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // a - f
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};
// clang-format on

bignum_t *bignum_set_hex(bignum_t *bn, char *hex, size_t size)
{
	int16_t sign = 1;

	// Check for negative sign
	if (hex[0] == '-')
	{
		sign = -1;

		hex += 1;
		size -= 1;
	}

	// Check for '0x'
	if (hex[0] == '0' && hex[1] == 'x')
	{
		hex += 2;
		size -= 2;
	}

	// Check for illegal characters
	for (size_t i = 0; i < size; ++i)
	{
		if (hex_to_nibble_table[(byte_t)hex[i]] == 255)
		{
			return NULL;
		}
	}

	if (bn == NULL)
	{
		bn = bignum_new(size * 8);

		if (bn == NULL)
		{
			return NULL;
		}
	}
	else
	{
		if (bn->size < size)
		{
			return NULL;
		}
	}

	size_t i = size - 1;
	uint32_t j = 0;

	while (1)
	{
		bn->words[j / 16] += hex_to_nibble_table[(byte_t)hex[i]] << (((j + 1) % 16) * 4);

		if (i == 0)
		{
			break;
		}

		++j;
		--i;
	};

	bn->sign = sign;
	bn->bits = bignum_bitcount(bn);

	return bn;
}

int32_t bignum_get_hex(bignum_t *bn, char *hex, size_t size)
{
	int32_t result = 0;

	size_t required_size = 2 + CEIL_DIV(bn->bits, 8);
	uint32_t count = CEIL_DIV(bn->bits, 8);
	byte_t *bytes = (byte_t *)bn->words;

	if (bn->sign < 0)
	{
		++required_size; // For '-' sign
	}

	if (size < required_size)
	{
		return -1;
	}

	if (bn->sign < 0)
	{
		hex[result++] = '-';
	}

	hex[result++] = '0';
	hex[result++] = 'x';

	for (int32_t i = count - 1; i >= 0; i -= 2)
	{
		hex[result++] = nibble_to_hex_table[bytes[i] >> 4];
		hex[result++] = nibble_to_hex_table[bytes[i] & 0xF];
	}

	return result;
}
