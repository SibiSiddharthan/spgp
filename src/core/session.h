/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_SESSION_H
#define SPGP_SESSION_H

#include <spgp.h>
#include <packet.h>
#include <mpi.h>

typedef enum _pgp_pkesk_version
{
	PGP_PKESK_V3 = 3,
	PGP_PKESK_V6 = 6
} pgp_pkesk_version;


typedef struct _pgp_pkesk_packet
{
	pgp_packet_header header;

	byte_t version; // 3 or 6
	byte_t anonymous;
	byte_t public_key_algorithm_id;
	byte_t session_key_algorithm_id;
	byte_t key_version;
	byte_t key_checksum[2];

	union {
		byte_t key_id[8];
		byte_t key_fingerprint[32];
	};

	uint16_t session_key_bits;
	void *session_key;

} pgp_pkesk_packet;

typedef struct _pgp_skesk_packet
{
	pgp_packet_header header;

	byte_t version; // 4 or 6
	byte_t symmetric_key_algorithm_id;
	byte_t aead_algorithm_id;
	byte_t s2k_algorithm_id;

	uint16_t session_key_bits;
	uint16_t iv_size;
	uint16_t tag_size;

	void *iv;
	void *tag;
	void *session_key;

} pgp_skesk_packet;

pgp_pkesk_packet *pgp_pkesk_packet_read(pgp_pkesk_packet *packet, void *data, size_t size);
size_t pgp_pkesk_packet_write(pgp_pkesk_packet *packet, void *ptr, size_t size);

pgp_skesk_packet *pgp_skesk_packet_read(pgp_skesk_packet *packet, void *data, size_t size);
size_t pgp_skesk_packet_write(pgp_skesk_packet *packet, void *ptr, size_t size);

#endif
