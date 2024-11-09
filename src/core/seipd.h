/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_SEIPD_H
#define SPGP_SEIPD_H

#include <spgp.h>
#include <packet.h>
#include <mpi.h>

typedef struct _pgp_sed_packet
{
	pgp_packet_header header;

	byte_t data[1];

} pgp_sed_packet;

typedef struct _pgp_seipd_packet
{
	pgp_packet_header header;

	byte_t version; // 1 or 2
	byte_t symmetric_key_algorithm_id;
	byte_t aead_algorithm_id;
	byte_t chunk_size;

	byte_t salt[32];

	uint16_t tag_size;
	uint32_t data_size;

	void *tag;
	void *data;

} pgp_seipd_packet;

pgp_sed_packet *pgp_sed_packet_read(pgp_sed_packet *packet, void *data, size_t size);
size_t pgp_sed_packet_write(pgp_sed_packet *packet, void *ptr, size_t size);

pgp_seipd_packet *pgp_seipd_packet_read(pgp_seipd_packet *packet, void *data, size_t size);
size_t pgp_seipd_packet_write(pgp_seipd_packet *packet, void *ptr, size_t size);

#endif
