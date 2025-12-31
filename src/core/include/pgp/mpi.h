/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_MPI_H
#define SPGP_MPI_H

#include <pgp/pgp.h>

typedef struct _mpi_t
{
	uint16_t bits;
	byte_t *bytes;
} mpi_t;

static inline uint32_t mpi_size(uint16_t bits)
{
	return sizeof(mpi_t) + CEIL_DIV(bits, 8);
}

static inline uint32_t mpi_octets(uint16_t bits)
{
	return 2 + CEIL_DIV(bits, 8);
}

mpi_t *mpi_init(void *ptr, size_t size, uint16_t bits);
mpi_t *mpi_new(uint16_t bits);
void mpi_delete(mpi_t *mpi);

uint32_t mpi_read(mpi_t *mpi, void *ptr, size_t size);
uint32_t mpi_write(mpi_t *mpi, void *ptr, size_t size);

uint32_t mpi_bitcount(void *ptr, size_t size);

#endif
