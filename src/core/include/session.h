/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_SESSION_H
#define SPGP_SESSION_H

#include <pgp.h>
#include <packet.h>
#include <error.h>
#include <key.h>
#include <mpi.h>
#include <s2k.h>

typedef enum _pgp_pkesk_version
{
	PGP_PKESK_V3 = 3,
	PGP_PKESK_V6 = 6
} pgp_pkesk_version;

typedef enum _pgp_skesk_version
{
	PGP_SKESK_V4 = 4,
	PGP_SKESK_V5 = 5,
	PGP_SKESK_V6 = 6
} pgp_skesk_version;

typedef struct _pgp_pkesk_packet
{
	pgp_packet_header header;

	byte_t version; // 3 or 6
	byte_t public_key_algorithm_id;
	byte_t symmetric_key_algorithm_id;
	byte_t key_octet_count;
	byte_t key_version;

	union
	{
		byte_t key_id[8];
		byte_t key_fingerprint[32];
	};

	uint16_t encrypted_session_key_octets;
	void *encrypted_session_key;

} pgp_pkesk_packet;

typedef struct _pgp_skesk_packet
{
	pgp_packet_header header;

	byte_t version; // 4, 5, 6
	byte_t symmetric_key_algorithm_id;
	byte_t aead_algorithm_id;
	pgp_s2k s2k;

	uint16_t session_key_size;
	uint16_t iv_size;
	uint16_t tag_size;

	byte_t iv[16];
	byte_t tag[16];
	byte_t session_key[48];

} pgp_skesk_packet;

typedef struct _pgp_rsa_kex
{
	mpi_t *c; // (m^e) mod n.
} pgp_rsa_kex;

typedef struct _pgp_elgamal_kex
{
	mpi_t *r; // (g^k) mod p
	mpi_t *s; // m * (y^k) mod p
} pgp_elgamal_kex;

typedef struct _pgp_ecdh_kex
{
	mpi_t *ephemeral_point;
	byte_t encoded_session_key_size;
	byte_t encoded_session_key[48];
} pgp_ecdh_kex;

typedef struct _pgp_x25519_kex
{
	byte_t symmetric_key_algorithm_id;
	byte_t octet_count;
	byte_t ephemeral_key[32];
	byte_t encrypted_session_key[40];
} pgp_x25519_kex;

typedef struct _pgp_x448_kex
{
	byte_t symmetric_key_algorithm_id;
	byte_t octet_count;
	byte_t ephemeral_key[56];
	byte_t encrypted_session_key[40];
} pgp_x448_kex;

// Public Key Encrypted Session Key Packet (Tag 1)
pgp_pkesk_packet *pgp_pkesk_packet_new(byte_t version, byte_t public_key_algorithm_id, byte_t session_key_algorithm_id);
void pgp_pkesk_packet_delete(pgp_pkesk_packet *packet);

pgp_pkesk_packet *pgp_pkesk_packet_session_key_encrypt(pgp_pkesk_packet *packet, pgp_key_packet *key, void *session_key,
													   size_t session_key_size, byte_t anonymous);
uint32_t pgp_pkesk_packet_session_key_decrypt(pgp_pkesk_packet *packet, pgp_key_packet *key, void *session_key, size_t session_key_size);

size_t pgp_pkesk_packet_get_session_key(pgp_pkesk_packet *packet, void *key, size_t size);

pgp_pkesk_packet *pgp_pkesk_packet_read(void *data, size_t size);
size_t pgp_pkesk_packet_write(pgp_pkesk_packet *packet, void *ptr, size_t size);
size_t pgp_pkesk_packet_print(pgp_pkesk_packet *packet, void *str, size_t size, uint32_t options);

// Symmetric Key Encrypted Session Key Packet (Tag 3)
pgp_error_t pgp_skesk_packet_new(pgp_skesk_packet **packet, byte_t version, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id,
								 pgp_s2k *s2k);
void pgp_skesk_packet_delete(pgp_skesk_packet *packet);

pgp_skesk_packet *pgp_skesk_packet_session_key_encrypt(pgp_skesk_packet *packet, void *password, size_t password_size, void *session_key,
													   size_t session_key_size, void *iv, size_t iv_size);
uint32_t pgp_skesk_packet_session_key_decrypt(pgp_skesk_packet *packet, void *password, size_t password_size, void *session_key,
											  size_t session_key_size);

pgp_error_t pgp_skesk_packet_read(pgp_skesk_packet **packet, void *data, size_t size);
size_t pgp_skesk_packet_write(pgp_skesk_packet *packet, void *ptr, size_t size);
size_t pgp_skesk_packet_print(pgp_skesk_packet *packet, void *str, size_t size);

#endif
