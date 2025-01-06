/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_SESSION_H
#define SPGP_SESSION_H

#include <spgp.h>
#include <packet.h>
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
	PGP_SKESK_V6 = 6
} pgp_skesk_version;

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

	uint16_t session_key_size;
	void *session_key;

} pgp_pkesk_packet;

typedef struct _pgp_skesk_packet
{
	pgp_packet_header header;

	byte_t version; // 4 or 6
	byte_t symmetric_key_algorithm_id;
	byte_t aead_algorithm_id;
	pgp_s2k s2k_algorithm;

	uint16_t session_key_size;
	uint16_t iv_size;
	uint16_t tag_size;

	void *iv;
	void *tag;
	void *session_key;

} pgp_skesk_packet;

typedef struct _pgp_rsa_encrypt
{
	mpi_t *c; // (m^e) mod n.
} pgp_rsa_encrypt;

typedef struct _pgp_elgamal_encrypt
{
	mpi_t *r; // (g^k) mod p
	mpi_t *s; // m * (y^k) mod p
} pgp_elgamal_encrypt;

typedef struct _pgp_ecdh_encrypt
{
	byte_t ephemeral_key_size;
	byte_t encrypted_session_key_size;

	void *ephemeral_key;
	void *encrypted_session_key;
} pgp_ecdh_encrypt;

typedef struct _pgp_x25519_encrypt
{
	byte_t ephemeral[32];
	byte_t size;
	byte_t algorithm;

	void *encrypted_session_key;
} pgp_x25519_encrypt;

typedef struct _pgp_x448_encrypt
{
	byte_t ephemeral[56];
	byte_t size;
	byte_t algorithm;

	void *encrypted_session_key;
} pgp_x448_encrypt;

pgp_pkesk_packet *pgp_pkesk_packet_read(pgp_pkesk_packet *packet, void *data, size_t size);
size_t pgp_pkesk_packet_write(pgp_pkesk_packet *packet, void *ptr, size_t size);


// Symmetric Key Encrypted Session Key Packet (Tag 3)
pgp_skesk_packet *pgp_skesk_packet_new(byte_t header_format, byte_t version, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id,
									   pgp_s2k *s2k);
void pgp_skesk_packet_delete(pgp_skesk_packet *packet);

pgp_skesk_packet *pgp_skesk_packet_session_key_encrypt(pgp_skesk_packet *packet, void *password, size_t password_size, void *session_key,
													   size_t session_key_size);
pgp_skesk_packet *pgp_skesk_packet_session_key_decrypt(pgp_skesk_packet *packet, void *password, size_t password_size, void *session_key,
													   size_t session_key_size);

pgp_skesk_packet *pgp_skesk_packet_read(pgp_skesk_packet *packet, void *data, size_t size);
size_t pgp_skesk_packet_write(pgp_skesk_packet *packet, void *ptr, size_t size);
size_t pgp_skesk_packet_print(pgp_skesk_packet *packet, void *str, size_t size);

#endif
