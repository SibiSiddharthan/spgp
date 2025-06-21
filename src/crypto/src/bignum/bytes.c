/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>

#include <bitscan.h>
#include <byteswap.h>

#include <string.h>

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

	// Zero the words.
	memset(bn->words, 0, bn->size);

	// Just copy the bytes straight to the word buffer.
	memcpy(bn->words, bytes, size);

	// Update bitcount.
	bn->bits = bignum_bitcount(bn);

	return bn;
}

bignum_t *bignum_set_bytes_be(bignum_t *bn, byte_t *bytes, size_t size)
{
	bn_word_t word = 0;
	size_t count = CEIL_DIV(size, BIGNUM_WORD_SIZE);
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

	// Zero the words.
	memset(bn->words, 0, bn->size);

	while (size >= BIGNUM_WORD_SIZE)
	{
		memcpy(&word, bytes + size - BIGNUM_WORD_SIZE, BIGNUM_WORD_SIZE);
		bn->words[pos++] = BSWAP_64(word);

		size -= BIGNUM_WORD_SIZE;
	}

	if (size != 0)
	{
		bn->words[count - 1] = 0;
		pos = 0;
	}

	// Most significant word
	switch (size % 8)
	{
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

uint32_t bignum_get_bytes_le(bignum_t *bn, byte_t *bytes, size_t size)
{
	size_t required_size = CEIL_DIV(bn->bits, 8);

	// If bn is zero output atleast 1 byte.
	if (bn->bits == 0)
	{
		if (size == 0)
		{
			return 0;
		}

		bytes[0] = 0x00;
		return 1;
	}

	if (size < required_size)
	{
		return 0;
	}

	memcpy(bytes, bn->words, required_size);

	return required_size;
}

uint32_t bignum_get_bytes_be(bignum_t *bn, byte_t *bytes, size_t size)
{
	bn_word_t word = 0;
	size_t count = CEIL_DIV(bn->bits, BIGNUM_BITS_PER_WORD);
	size_t required_size = CEIL_DIV(bn->bits, 8);
	size_t pos = 0;
	size_t spill = 0;

	// If bn is zero output atleast 1 byte.
	if (bn->bits == 0)
	{
		if (size == 0)
		{
			return 0;
		}

		bytes[0] = 0x00;
		return 1;
	}

	if (size < required_size)
	{
		return 0;
	}

	// Most significant word
	spill = required_size % BIGNUM_WORD_SIZE;
	word = BSWAP_64(bn->words[count - 1]);

	if (spill == 0)
	{
		memcpy(bytes, &word, BIGNUM_WORD_SIZE);
		pos += BIGNUM_WORD_SIZE;
	}
	else
	{
		memcpy(bytes, (byte_t *)&word + BIGNUM_WORD_SIZE - spill, spill);
		pos += required_size % BIGNUM_WORD_SIZE;
	}

	size_t i = count - 2;

	while (1)
	{
		// If required_size is not multiple of BIGNUM_WORD_SIZE, a lot of unaligned accesses will happen.
		// Just call memcpy to deal with it.
		word = BSWAP_64(bn->words[i]);
		memcpy(bytes + pos, &word, BIGNUM_WORD_SIZE);

		pos += BIGNUM_WORD_SIZE;

		if (i == 0)
		{
			break;
		}

		--i;
	}

	return required_size;
}

uint32_t bignum_get_bytes_be_padded(bignum_t *bn, byte_t *bytes, size_t size)
{
	size_t required_size = CEIL_DIV(bn->bits, 8);
	size_t pad = size - required_size;

	if (size < required_size)
	{
		return 0;
	}

	// Pad the start with zeros.
	memset(bytes, 0x00, pad);
	bignum_get_bytes_be(bn, bytes + pad, required_size);

	return size;
}

static const char nibble_to_hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

// clang-format off
static const byte_t hex_to_nibble_table[256] = 
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,                       // 0 - 9
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // A - F
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // a - f
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
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
	if (hex[0] == '-' || hex[0] == '+')
	{
		sign = hex[0] == '-' ? -1 : 1;

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
		if (bn->size < CEIL_DIV(size, 2))
		{
			return NULL;
		}
	}

	// Zero the words.
	memset(bn->words, 0, bn->size);

	size_t i = size - 1;
	uint32_t j = 0;

	while (1)
	{
		bn->words[j / 16] += (bn_word_t)hex_to_nibble_table[(byte_t)hex[i]] << ((j % 16) * 4);

		if (i == 0)
		{
			break;
		}

		++j;
		--i;
	};

	bn->sign = sign;
	bn->bits = bignum_bitcount(bn);

	if (bn->bits == 0)
	{
		bn->sign = 1;
	}

	return bn;
}

uint32_t bignum_get_hex(bignum_t *bn, char *hex, size_t size)
{
	int32_t result = 0;

	size_t required_size = 2 + CEIL_DIV(bn->bits, 8);
	uint32_t count = CEIL_DIV(bn->bits, 8);
	byte_t *bytes = (byte_t *)bn->words;

	if (bn->bits == 0)
	{
		if (size < 3)
		{
			return 0;
		}

		hex[result++] = '0';
		hex[result++] = 'x';
		hex[result++] = '0';

		return result;
	}

	if (bn->sign < 0)
	{
		++required_size; // For '-' sign
	}

	if (size < required_size)
	{
		return 0;
	}

	if (bn->sign < 0)
	{
		hex[result++] = '-';
	}

	hex[result++] = '0';
	hex[result++] = 'x';

	// Most significant byte
	if ((bytes[count - 1] >> 4) != 0)
	{
		// Only print the nibble if it is not zero.
		// Most bignumber implementations do this.
		hex[result++] = nibble_to_hex_table[bytes[count - 1] >> 4];
	}

	hex[result++] = nibble_to_hex_table[bytes[count - 1] & 0xF];

	for (int32_t i = count - 2; i >= 0; --i)
	{
		hex[result++] = nibble_to_hex_table[bytes[i] >> 4];
		hex[result++] = nibble_to_hex_table[bytes[i] & 0xF];
	}

	return result;
}
