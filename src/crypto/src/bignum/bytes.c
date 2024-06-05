/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include <byteswap.h>
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
		if ((bn->count / BIGNUM_WORD_SIZE) < size)
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
	uint64_t *qword = (uint64_t *)bytes;
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
		if ((bn->count / BIGNUM_WORD_SIZE) < size)
		{
			return NULL;
		}
	}

	// Copy 64-bit words at a time, BSWAP'd.
	for (size_t i = 0; i < count - 1; ++i)
	{
		bn->words[i] = BSWAP_64(qword[count - i - 1]);
	}

	bn->words[count - 1] = 0;

	switch (size % 8)
	{
	case 0:
		bn->words[count - 1] = BSWAP_64(qword[0]);
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
	size_t required_size = ROUND_UP(bn->bits, 8) / 8;

	if (required_size < size)
	{
		return -1;
	}

	memcpy(bytes, bn->words, size);

	return 0;
}

int32_t bignum_get_bytes_be(bignum_t *bn, byte_t *bytes, size_t size)
{
	uint64_t *qword = (uint64_t *)bytes;
	size_t count = ROUND_UP(bn->bits, BIGNUM_WORD_SIZE) / BIGNUM_WORD_SIZE;
	size_t required_size = ROUND_UP(bn->bits, 8) / 8;

	if (required_size < size)
	{
		return -1;
	}

	for (size_t i = 0; i < count; ++i)
	{
		qword[i] = BSWAP_64(bn->words[count - i - 1]);
	}

	return 0;
}
