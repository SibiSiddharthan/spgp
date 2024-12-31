/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_KEY_H
#define SPGP_KEY_H

#include <spgp.h>
#include <packet.h>
#include <s2k.h>
#include <mpi.h>

typedef enum _pgp_key_version
{
	PGP_KEY_V2 = 2, // NOTE : Version 2 is identical to version 3.
	PGP_KEY_V3 = 3,
	PGP_KEY_V4 = 4,
	PGP_KEY_V6 = 6
} pgp_key_version;

typedef struct _pgp_public_key_packet
{
	pgp_packet_header header;

	byte_t version; // 3, 4, 6
	uint32_t key_creation_time;
	uint16_t key_expiry_days;
	byte_t public_key_algorithm_id;

	uint32_t key_data_size;
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
	byte_t aead_algorithm_id;

	byte_t s2k_usage;
	pgp_s2k s2k_algorithm;

	byte_t iv[16];
	byte_t key_checksum[2];

	uint32_t public_key_data_size;
	uint32_t private_key_data_size;

	void *public_key_data;
	void *private_key_data;

} pgp_secret_key_packet, _pgp_secret_subkey_packet;

typedef struct _pgp_rsa_key
{
	// Public
	mpi_t *n, *e;

	// Private
	mpi_t *d;
	mpi_t *p, *q;
	mpi_t *u;
} pgp_rsa_key;

typedef struct _pgp_dsa_key
{
	// Public
	mpi_t *p, *q;
	mpi_t *g;
	mpi_t *y;

	// Private
	mpi_t *x;
} pgp_dsa_key;

typedef struct _pgp_elgamal_key
{
	// Public
	mpi_t *p;
	mpi_t *g;
	mpi_t *y;

	// Private
	mpi_t *x;
} pgp_elgamal_key;

typedef struct _pgp_ecdsa_key
{
	// Public
	byte_t oid_size;
	byte_t oid[16];

	byte_t point_size;
	void *point;

	// Private
	mpi_t *x;
} pgp_ecdsa_key;

typedef struct _pgp_ecdh_key
{
	// Public
	byte_t oid_size;
	byte_t oid[16];

	struct
	{
		byte_t size;
		byte_t extensions;
		byte_t hash_algorithm_id;
		byte_t symmetric_key_algorithm_id;
	} kdf;

	byte_t point_size;
	void *point;

	// Private
	mpi_t *x;
} pgp_ecdh_key;

typedef struct _pgp_x25519_key
{
	byte_t public_key[32];
	byte_t private_key[32];
} pgp_x25519_key;

typedef struct _pgp_x448_key
{
	byte_t public_key[56];
	byte_t private_key[56];
} pgp_x448_key;

typedef struct _pgp_ed25519_key
{
	byte_t public_key[32];
	byte_t private_key[32];
} pgp_ed25519_key;

typedef struct _pgp_ed448_key
{
	byte_t public_key[57];
	byte_t private_key[57];
} pgp_ed448_key;

pgp_public_key_packet *pgp_public_key_packet_read(pgp_public_key_packet *packet, void *data, size_t size);
size_t pgp_public_key_packet_write(pgp_public_key_packet *packet, void *ptr, size_t size);

pgp_secret_key_packet *pgp_secret_key_packet_read(pgp_secret_key_packet *packet, void *data, size_t size);
size_t pgp_secret_key_packet_write(pgp_secret_key_packet *packet, void *ptr, size_t size);

#endif
