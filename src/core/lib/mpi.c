/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
#include <mpi.h>

#include <stdlib.h>
#include <string.h>

mpi_t *mpi_init(void *ptr, size_t size, uint16_t bits)
{
	mpi_t *mpi = ptr;
	size_t required_size = mpi_size(bits);

	if (size < required_size)
	{
		return NULL;
	}

	memset(mpi, 0, required_size);

	mpi->bits = ROUND_UP(bits, 8);
	mpi->bytes = PTR_OFFSET(mpi, sizeof(mpi_t));

	return mpi;
}

mpi_t *mpi_new(uint16_t bits)
{
	mpi_t *mpi = NULL;
	size_t required_size = mpi_size(bits);

	mpi = malloc(required_size);

	if (mpi == NULL)
	{
		return NULL;
	}

	memset(mpi, 0, required_size);

	mpi->bits = ROUND_UP(bits, 8);
	mpi->bytes = PTR_OFFSET(mpi, sizeof(mpi_t));

	return mpi;
}

void mpi_delete(mpi_t *mpi)
{
	if (mpi == NULL)
	{
		return;
	}

	memset(mpi->bytes, 0, CEIL_DIV(mpi->bits, 8));

	free(mpi);
}

// See RFC 9580 - OpenPGP, Section 3.2 Multiprecision Integers.
uint32_t mpi_read(mpi_t *mpi, void *ptr, size_t size)
{
	uint32_t pos = 0;
	uint16_t bytes = 0;

	// Get the number of bits
	LOAD_16BE(&mpi->bits, ptr);
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
	byte_t *out = ptr;

	if (size < required_size)
	{
		return 0;
	}

	LOAD_16BE(out, &mpi->bits);
	memcpy(out + sizeof(uint16_t), mpi->bytes, CEIL_DIV(mpi->bits, 8));

	return required_size;
}
