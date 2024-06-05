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
		if (ROUND_UP(bn->bits, 8) / 8 < size)
		{
			return NULL;
		}
	}

	memcpy(bn->qwords, bytes, size);

	return bn;
}

bignum_t *bignum_set_bytes_be(bignum_t *bn, byte_t *bytes, size_t size)
{
	uint64_t *qword = (uint64_t *)bytes;
	size_t count = ROUND_UP(size, 8) / 8;
	size_t required_size = ROUND_UP(bn->bits, 8) / 8;
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
		if (ROUND_UP(bn->bits, 8) / 8 < size)
		{
			return NULL;
		}
	}

	for (size_t i = 0; i < count - 1; ++i)
	{
		bn->qwords[i] = BSWAP_64(qword[count - i - 1]);
	}

	bn->qwords[count - 1] = 0;

	switch (size % 8)
	{
	case 0:
		bn->qwords[count - 1] = BSWAP_64(qword[0]);
		break;
	case 7:
		bn->qwords[count - 1] = bytes[pos++];
		bn->qwords[count - 1] <<= 8;
		// Fallthrough
	case 6:
		bn->qwords[count - 1] += bytes[pos++];
		bn->qwords[count - 1] <<= 8;
		// Fallthrough
	case 5:
		bn->qwords[count - 1] += bytes[pos++];
		bn->qwords[count - 1] <<= 8;
		// Fallthrough
	case 4:
		bn->qwords[count - 1] += bytes[pos++];
		bn->qwords[count - 1] <<= 8;
		// Fallthrough
	case 3:
		bn->qwords[count - 1] += bytes[pos++];
		bn->qwords[count - 1] <<= 8;
		// Fallthrough
	case 2:
		bn->qwords[count - 1] += bytes[pos++];
		bn->qwords[count - 1] <<= 8;
		// Fallthrough
	case 1:
		bn->qwords[count - 1] += bytes[pos++];
	}

	return bn;
}

int32_t bignum_get_bytes_le(bignum_t *bn, byte_t *bytes, size_t size)
{
	size_t required_size = ROUND_UP(bn->bits, 8) / 8;

	if (required_size < size)
	{
		return -1;
	}

	memcpy(bytes, bn->qwords, size);

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
		qword[i] = BSWAP_64(bn->qwords[count - i - 1]);
	}

	return 0;
}
