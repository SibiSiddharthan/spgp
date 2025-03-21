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
	PGP_KEY_V5 = 5,
	PGP_KEY_V6 = 6
} pgp_key_version;

typedef enum _pgp_key_type
{
	PGP_KEY_TYPE_PUBLIC = 1,
	PGP_KEY_TYPE_SECRET = 2
} pgp_key_type;

#define PGP_KEY_ID_SIZE 8

// Key Fingerprint Sizes
#define PGP_KEY_V3_FINGERPRINT_SIZE  16
#define PGP_KEY_V4_FINGERPRINT_SIZE  20
#define PGP_KEY_V5_FINGERPRINT_SIZE  32
#define PGP_KEY_V6_FINGERPRINT_SIZE  32
#define PGP_KEY_MAX_FINGERPRINT_SIZE 32

typedef struct _pgp_key_packet
{
	pgp_packet_header header;

	byte_t version; // 3, 4, 5, 6
	byte_t type;
	byte_t flags;

	uint32_t key_creation_time;

	union
	{
		uint16_t key_expiry_days;
		uint32_t key_expiry_time;
	};

	byte_t public_key_algorithm_id;
	byte_t symmetric_key_algorithm_id;
	byte_t aead_algorithm_id;

	byte_t s2k_usage;
	pgp_s2k s2k;

	byte_t iv_size;
	byte_t iv[16];

	uint16_t key_checksum;

	uint32_t public_key_data_octets;
	uint32_t private_key_data_octets;
	uint32_t encrypted_octets;

	void *key;
	void *encrypted;

} pgp_key_packet;

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
	// Parameters
	mpi_t *p, *q;
	mpi_t *g;

	mpi_t *y; // Public
	mpi_t *x; // Private
} pgp_dsa_key;

typedef struct _pgp_elgamal_key
{
	// Public
	mpi_t *p;
	mpi_t *g;

	mpi_t *y; // Public
	mpi_t *x; // Private
} pgp_elgamal_key;

typedef struct _pgp_ecdsa_key
{
	// Parameters
	byte_t curve;
	byte_t oid_size;
	byte_t oid[16];

	mpi_t *point; // Public
	mpi_t *x;     // Point
} pgp_ecdsa_key, pgp_eddsa_key;

typedef struct _pgp_ecdh_key
{
	// Parameters
	byte_t curve;
	byte_t oid_size;
	byte_t oid[16];

	struct
	{
		byte_t size;
		byte_t extensions;
		byte_t hash_algorithm_id;
		byte_t symmetric_key_algorithm_id;
	} kdf;

	mpi_t *point; // Public
	mpi_t *x;     // Point
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

void *pgp_key_generate(byte_t public_key_algorithm_id);

pgp_key_packet *pgp_key_packet_new(byte_t version, byte_t subkey, uint32_t key_creation_time, uint16_t key_expiry_days,
								   byte_t public_key_algorithm_id, void *key);
void pgp_key_packet_delete(pgp_key_packet *packet);

pgp_key_packet *pgp_key_packet_encrypt(pgp_key_packet *packet, void *passphrase, size_t passphrase_size, byte_t s2k_usage, pgp_s2k *s2k,
									   void *iv, byte_t iv_size, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id);
pgp_key_packet *pgp_key_packet_decrypt(pgp_key_packet *packet, void *passphrase, size_t passphrase_size);

pgp_key_packet *pgp_public_key_packet_read(void *data, size_t size);
size_t pgp_public_key_packet_write(pgp_key_packet *packet, void *ptr, size_t size);
size_t pgp_public_key_packet_print(pgp_key_packet *packet, void *str, size_t size, uint32_t options);

pgp_key_packet *pgp_secret_key_packet_read(void *data, size_t size);
size_t pgp_secret_key_packet_write(pgp_key_packet *packet, void *ptr, size_t size);
size_t pgp_secret_key_packet_print(pgp_key_packet *packet, void *str, size_t size, uint32_t options);

pgp_key_packet *pgp_key_packet_read(void *data, size_t size);
size_t pgp_key_packet_write(pgp_key_packet *packet, void *ptr, size_t size);
size_t pgp_key_packet_print(pgp_key_packet *packet, void *str, size_t size, uint32_t options);

uint32_t pgp_key_fingerprint(void *key, void *fingerprint, uint32_t size);
uint32_t pgp_key_id(void *key, byte_t id[8]);

void *pgp_rsa_generate_key(uint32_t bits);
void *pgp_dsa_generate_key(uint32_t p_bits, uint32_t q_bits);

void *pgp_ecdsa_generate_key(pgp_elliptic_curve_id curve);
void *pgp_ecdh_generate_key(pgp_elliptic_curve_id curve, byte_t hash_algorithm_id, byte_t symmetric_key_algorithm_id);

void pgp_x25519_generate_key(pgp_x25519_key *key);
void pgp_x448_generate_key(pgp_x448_key *key);

void pgp_ed25519_generate_key(pgp_ed25519_key *key);
void pgp_ed448_generate_key(pgp_ed448_key *key);

pgp_rsa_key *pgp_rsa_key_new();
void pgp_rsa_key_delete(pgp_rsa_key *key);

pgp_dsa_key *pgp_dsa_key_new();
void pgp_dsa_key_delete(pgp_dsa_key *key);

pgp_ecdsa_key *pgp_ecdsa_key_new();
void pgp_ecdsa_key_delete(pgp_ecdsa_key *key);

pgp_ecdh_key *pgp_ecdh_key_new();
void pgp_ecdh_key_delete(pgp_ecdh_key *key);

#endif
