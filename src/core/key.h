/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_KEY_H
#define SPGP_KEY_H

#include <spgp.h>
#include <packet.h>
#include <mpi.h>

typedef struct _pgp_public_key_packet
{
	pgp_packet_header header;

	byte_t version; // 3, 4, 6
	uint32_t key_creation_time;
	uint16_t key_expiry_days;
	byte_t public_key_algorithm_id;

	uint16_t key_bits;
	void *key_data;

} pgp_public_key_packet, pgp_public_subkey_packet;

typedef struct _pgp_secret_key_packet
{
	pgp_packet_header header;

	byte_t version; // 3, 4, 6
	uint32_t key_creation_time;
	uint16_t key_expiry_days;
	byte_t public_key_algorithm_id;
	byte_t symmetric_key_algorithm_id;

	union {
		byte_t aead_algorithm_id;
		byte_t s2k_algorithm_id;
	};

	byte_t iv[16];
	byte_t key_checksum[2];

	uint16_t public_key_bits;
	uint16_t private_key_bits;

	void *public_key_data;
	void *private_key_data;

} pgp_secret_key_packet, _pgp_secret_subkey_packet;

#endif
