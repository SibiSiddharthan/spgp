/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <mpi.h>

#include <stdlib.h>
#include <string.h>

mpi_t *mpi_init_checked(void *ptr, size_t mpi_size, uint32_t bits)
{
	mpi_t *mpi = ptr;

	memset(mpi, 0, mpi_size);
	mpi->bits = bits;

	return mpi;
}

mpi_t *mpi_init(void *ptr, size_t size, uint16_t bits)
{
	mpi_t *mpi = ptr;
	size_t required_size = sizeof(mpi_t);

	required_size += CEIL_DIV(mpi->bits, 8);

	if (size < required_size)
	{
		return NULL;
	}

	return mpi_init_checked(mpi, required_size, bits);
}

mpi_t *mpi_new(uint16_t bits)
{
	mpi_t *mpi = NULL;
	size_t size = sizeof(mpi_t);

	size += CEIL_DIV(mpi->bits, 8);

	mpi = (mpi_t *)malloc(size);

	if (mpi == NULL)
	{
		return NULL;
	}

	return mpi_init_checked(mpi, size, bits);
}

void mpi_delete(mpi_t *mpi)
{
	free(mpi);
}

mpi_t *mpi_from_bn(mpi_t *mpi, bignum_t *bn)
{
	if (mpi == NULL)
	{
		mpi = mpi_new(bn->bits);

		if (mpi == NULL)
		{
			return NULL;
		}
	}

	if (mpi->bits < bn->bits)
	{
		return NULL;
	}

	// Get the bytes
	mpi->bits = bn->bits;
	bignum_get_bytes_be(bn, mpi->bytes, CEIL_DIV(mpi->bits, 8));

	return mpi;
}

// See RFC 9580 - OpenPGP, Section 3.2 Multiprecision Integers.
uint32_t mpi_read(mpi_t *mpi, void *ptr, size_t size)
{
	uint32_t pos = 0;
	uint16_t bits_be = 0;
	uint16_t bytes = 0;

	// Get the number of bits
	LOAD_16(&bits_be, ptr);
	mpi->bits = BSWAP_16(bits_be);
	pos += 2;

	bytes = CEIL_DIV(mpi->bits, 8);

	if (size < (2 + bytes))
	{
		return 0;
	}

	memcpy(mpi->bytes, PTR_OFFSET(ptr, 2), bytes);
	pos += bytes;

	return pos;
}

uint32_t mpi_write(mpi_t *mpi, void *ptr, size_t size)
{
	// 2 bytes for the bits + the number in big endian form.
	uint16_t required_size = 2 + CEIL_DIV(mpi->bits, 8);
	uint16_t bits_be = BSWAP_16(mpi->bits);
	byte_t *out = ptr;

	if (size < required_size)
	{
		return -1;
	}

	LOAD_16(out, &bits_be);
	memcpy(out + sizeof(uint16_t), mpi->bytes, CEIL_DIV(mpi->bits, 8));

	return required_size;
}
