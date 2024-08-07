/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_PACKET_H
#define SPGP_PACKET_H

#include <spgp.h>

// Refer RFC 9580 - OpenPGP, Section 5 Packet Types

typedef enum _pgp_packet_type
{
	PGP_RESERVED = 0,   // Reserved Packet
	PGP_PKESK = 1,      // Public Key Encrypted Session Key Packet
	PGP_SIG = 2,        // Signature Packet
	PGP_SKESK = 3,      // Symmetric Key Encrypted Session Key Packet
	PGP_OPS = 4,        // One-Pass Signature Packet
	PGP_SECKEY = 5,     // Secret Key Packet
	PGP_PUBKEY = 6,     // Public Key Packet
	PGP_SECSUBKEY = 7,  // Secret Subkey Packet
	PGP_COMP = 8,       // Compressed Data Packet
	PGP_SED = 9,        // Symmetrically Encrypted Data Packet
	PGP_MARKER = 10,    // Marker Packet
	PGP_LIT = 11,       // Literal Data Packet
	PGP_TRUST = 12,     // Trust Packet
	PGP_UID = 13,       // User ID Packet
	PGP_PUBSUBKEY = 14, // Public Subkey Packet
	PGP_UAT = 17,       // User Attribute Packet
	PGP_SEIPD = 18,     // Symmetrically Encrypted and Integrity Protected Data Packet
	PGP_MDC = 19,       // Modification Detection Code Packet
	PGP_PADDING = 21    // Padding Packet

} pgp_packet_type;

typedef enum _pgp_packet_header_type
{
	PGP_HEADER = 0,
	PGP_LEGACY_HEADER = 1
} pgp_packet_header_type;

typedef struct _pgp_packet_header
{
	byte_t tag;
	uint32_t size;
} pgp_packet_header;

typedef struct _pgp_pkesk_packet
{
	pgp_packet_header header;

	byte_t version; // 3 or 6

	union {
		struct
		{
			byte_t key_id[8];
			byte_t algorithm_id;
		} v3;

		struct
		{
			byte_t size;
			byte_t version;

			union {
				byte_t fingerprint_v4[20];
				byte_t fingerprint_v6[32];
			};

			byte_t algorithm_id;
		} v6;
	};

	void *key_data;

} pgp_pkesk_packet;

typedef struct _pgp_public_key_packet
{
	pgp_packet_header header;

	byte_t version;
	byte_t algorithm_id;
	uint16_t expiry_days;
	uint32_t creation_timestamp;

	uint32_t key_material_size;
	void *key_material;
} pgp_pubkey_packet, pgp_pubsubkey_packet;

typedef struct _pgp_secret_key_packet
{
	pgp_packet_header header;

	byte_t version;
	byte_t algorithm_id;
	uint16_t expiry_days;
	uint32_t creation_timestamp;

	uint32_t key_material_size;
	void *key_material;
} pgp_seckey_packet, pgp_secsubkey_packet;

typedef struct _pgp_comp_packet
{
	pgp_packet_header header;

	byte_t compression_algorithm_id;
	byte_t data[1];
} pgp_comp_packet;

typedef struct _pgp_marker_packet
{
	pgp_packet_header header;
	byte_t marker[3]; // "PGP" (0x50, 0x47, 0x50)
} pgp_marker_packet;

typedef struct _pgp_padding_packet
{
	pgp_packet_header header;
	byte_t data[1];
} pgp_padding_packet;

typedef struct _pgp_mdc_packet
{
	pgp_packet_header header;
	byte_t sha1_hash[20];
} pgp_mdc_packet;

typedef struct _pgp_trust_packet
{
	pgp_packet_header header;
	void *placeholder;
} pgp_trust_packet;

#endif
