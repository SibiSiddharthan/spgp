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

#define PGP_KEY_ID_SIZE 8

// Key Fingerprint Sizes
#define PGP_KEY_V3_FINGERPRINT_SIZE 16
#define PGP_KEY_V4_FINGERPRINT_SIZE 20
#define PGP_KEY_V6_FINGERPRINT_SIZE 32

typedef struct _pgp_public_key_packet
{
	pgp_packet_header header;

	byte_t version; // 3, 4, 6
	uint32_t key_creation_time;
	uint16_t key_expiry_days;
	byte_t public_key_algorithm_id;

	uint32_t key_data_size;
	uint32_t key_data_octets;
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
	pgp_s2k s2k;

	byte_t iv_size;
	byte_t iv[16];
	byte_t key_checksum[2];

	uint32_t public_key_data_size;
	uint32_t public_key_data_octets;

	uint32_t private_key_data_size;
	uint32_t private_key_data_octets;

	void *public_key_data;
	void *private_key_data;

} pgp_secret_key_packet, _pgp_secret_subkey_packet;

typedef struct _pgp_rsa_public_key
{
	mpi_t *n, *e;
} pgp_rsa_public_key;

typedef struct _pgp_rsa_private_key
{
	mpi_t *d;
	mpi_t *p, *q;
	mpi_t *u;
} pgp_rsa_private_key;

typedef struct _pgp_dsa_public_key
{
	mpi_t *p, *q;
	mpi_t *g;
	mpi_t *y;
} pgp_dsa_public_key;

typedef struct _pgp_dsa_private_key
{
	mpi_t *x;
} pgp_dsa_private_key;

typedef struct _pgp_elgamal_public_key
{
	mpi_t *p;
	mpi_t *g;
	mpi_t *y;
} pgp_elgamal_public_key;

typedef struct _pgp_elgamal_private_key
{
	mpi_t *x;
} pgp_elgamal_private_key;

typedef struct _pgp_ecdsa_public_key
{
	byte_t oid_size;
	byte_t oid[16];

	mpi_t *point;
} pgp_ecdsa_public_key;

typedef struct _pgp_ecdsa_private_key
{
	mpi_t *x;
} pgp_ecdsa_private_key;

typedef struct _pgp_ecdh_public_key
{
	byte_t oid_size;
	byte_t oid[16];

	struct
	{
		byte_t size;
		byte_t extensions;
		byte_t hash_algorithm_id;
		byte_t symmetric_key_algorithm_id;
	} kdf;

	mpi_t *point;
} pgp_ecdh_public_key;

typedef struct _pgp_ecdh_private_key
{
	mpi_t *x;
} pgp_ecdh_private_key;

typedef struct _pgp_x25519_public_key
{
	byte_t public_key[32];
} pgp_x25519_public_key;

typedef struct _pgp_x25519_private_key
{
	byte_t private_key[32];
} pgp_x25519_private_key;

typedef struct _pgp_x448_public_key
{
	byte_t public_key[56];
} pgp_x448_public_key;

typedef struct _pgp_x448_private_key
{
	byte_t private_key[56];
} pgp_x448_private_key;

typedef struct _pgp_ed25519_public_key
{
	byte_t public_key[32];
} pgp_ed25519_public_key;

typedef struct _pgp_ed25519_private_key
{
	byte_t private_key[32];
} pgp_ed25519_private_key;

typedef struct _pgp_ed448_public_key
{
	byte_t public_key[57];
} pgp_ed448_public_key;

typedef struct _pgp_ed448_private_key
{
	byte_t private_key[57];
} pgp_ed448_private_key;

uint32_t pgp_generate_key(byte_t public_key_algorithm_id, void **public_key, void **private_key);

pgp_public_key_packet *pgp_public_key_packet_new(pgp_packet_type type, pgp_key_version version, uint32_t key_creation_time,
												 uint16_t key_expiry_days, byte_t public_key_algorithm_id, void *key_data,
												 uint32_t key_data_size);
void pgp_public_key_packet_delete(pgp_public_key_packet *packet);

pgp_public_key_packet *pgp_public_key_packet_read(void *data, size_t size);
size_t pgp_public_key_packet_write(pgp_public_key_packet *packet, void *ptr, size_t size);
size_t pgp_public_key_packet_print(pgp_public_key_packet *packet, void *str, size_t size);

pgp_secret_key_packet *pgp_secret_key_packet_new(pgp_packet_type type, pgp_key_version version, uint32_t key_creation_time,
												 uint16_t key_expiry_days, byte_t public_key_algorithm_id,
												 byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id, byte_t s2k_usage,
												 pgp_s2k *s2k_algorithm, void *iv, byte_t iv_size, void *passphrase, size_t passphrase_size,
												 void *public_key_data, uint32_t public_key_data_size, void *private_key_data,
												 uint32_t private_key_data_size);
void pgp_secret_key_packet_delete(pgp_secret_key_packet *packet);

pgp_secret_key_packet *pgp_secret_key_packet_read(void *data, size_t size);
size_t pgp_secret_key_packet_write(pgp_secret_key_packet *packet, void *ptr, size_t size);

uint32_t pgp_key_fingerprint(void *key, void *fingerprint, uint32_t size);
uint32_t pgp_key_id(void *key, byte_t id[8]);

#endif
