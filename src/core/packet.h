/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

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
	byte_t header_size;
	uint32_t body_size;
} pgp_packet_header;

typedef struct _pgp_compressed_packet
{
	pgp_packet_header header;

	byte_t compression_algorithm_id;
	byte_t data[1];
} pgp_compresed_packet;

typedef struct _pgp_marker_packet
{
	pgp_packet_header header;
	byte_t marker[3]; // "PGP" (0x50, 0x47, 0x50)
} pgp_marker_packet;

typedef enum _pgp_literal_data_format
{
	PGP_LITERAL_DATA_BINARY = 0x62, // 'b'
	PGP_LITERAL_DATA_UTF8 = 0x75,   // 'u',
	PGP_LITERAL_DATA_TEXT = 0x74    // 't'

} _pgp_literal_data_format;

typedef struct _pgp_literal_packet
{
	pgp_packet_header header;

	byte_t format;
	uint32_t date;

	byte_t filename_size;
	void *filename;

	uint32_t data_size;
	void *data;

} pgp_literal_packet;

typedef struct _pgp_user_id_packet
{
	pgp_packet_header header;
	byte_t user_id[1];
} pgp_user_id_packet;

typedef enum _pgp_user_attribute_subpacket_type
{
	PGP_USER_ATTRIBUTE_IMAGE = 1
} pgp_user_attribute_subpacket_type;

typedef enum _pgp_user_attribute_image_encoding
{
	PGP_USER_ATTRIBUTE_IMAGE_JPEG = 1
} pgp_user_attribute_image_encoding;

typedef struct _pgp_user_attribute_subpacket_header
{
	byte_t type;
	byte_t header_size;
	uint32_t body_size;
} pgp_user_attribute_subpacket_header;

typedef struct _pgp_user_attribute_image_subpacket
{
	pgp_user_attribute_subpacket_header header;

	uint16_t image_header_size;  // 1
	byte_t image_header_version; // 1
	byte_t image_encoding;
	byte_t reserved[12]; // 12 zero octets

	void *image_data;

} pgp_user_attribute_image_subpacket;

typedef struct _pgp_user_attribute_packet
{
	pgp_packet_header header;

	uint16_t subpacket_count;
	void **subpackets;
} pgp_user_attribute_packet;

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

typedef enum _pgp_trust_level
{
	PGP_TRUST_NEVER = 0,
	PGP_TRUST_FULL = 1
} pgp_trust_level;

typedef struct _pgp_trust_packet
{
	pgp_packet_header header;
	byte_t level;
} pgp_trust_packet;

pgp_packet_header pgp_packet_header_read(void *data, size_t size);
uint32_t pgp_packet_header_write(pgp_packet_header *header, void *ptr);

pgp_compresed_packet *pgp_compressed_packet_read(pgp_compresed_packet *packet, void *data, size_t size);
size_t pgp_compressed_packet_write(pgp_compresed_packet *packet, void *ptr, size_t size);

pgp_marker_packet *pgp_marker_packet_read(pgp_marker_packet *packet, void *data, size_t size);
size_t pgp_marker_packet_write(pgp_marker_packet *packet, void *ptr, size_t size);

pgp_literal_packet *pgp_literal_packet_read(pgp_literal_packet *packet, void *data, size_t size);
size_t pgp_literal_packet_write(pgp_literal_packet *packet, void *ptr, size_t size);

pgp_user_id_packet *pgp_user_id_packet_read(pgp_user_id_packet *packet, void *data, size_t size);
size_t pgp_user_id_packet_write(pgp_user_id_packet *packet, void *ptr, size_t size);

pgp_user_attribute_packet *pgp_user_attribute_packet_read(pgp_user_attribute_packet *packet, void *data, size_t size);
size_t pgp_user_attribute_packet_write(pgp_user_attribute_packet *packet, void *ptr, size_t size);

pgp_padding_packet *pgp_padding_packet_read(pgp_padding_packet *packet, void *data, size_t size);
size_t pgp_padding_packet_write(pgp_padding_packet *packet, void *ptr, size_t size);

pgp_mdc_packet *pgp_mdc_packet_read(pgp_mdc_packet *packet, void *data, size_t size);
size_t pgp_mdc_packet_write(pgp_mdc_packet *packet, void *ptr, size_t size);

pgp_trust_packet *pgp_trust_packet_read(pgp_trust_packet *packet, void *data, size_t size);
size_t pgp_trust_packet_write(pgp_trust_packet *packet, void *ptr, size_t size);

#endif
