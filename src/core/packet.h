/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_PACKET_H
#define SPGP_PACKET_H

#include <pgp.h>
#include <stream.h>

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
	PGP_AEAD = 20,      // AEAD Encrypted Data Packet
	PGP_PADDING = 21,   // Padding Packet
	PGP_KEYDEF = 60,    // Key Definition Packet (Private)
	PGP_KEYRING = 61,   // Keyring Packet (Private)
} pgp_packet_type;

#define PGP_SUBPACKET_TAG_MASK 0x7F

typedef enum _pgp_packet_header_format
{
	PGP_HEADER = 0,
	PGP_LEGACY_HEADER = 1
} pgp_packet_header_format;

typedef struct _pgp_packet_header
{
	byte_t tag;
	byte_t header_size;
	uint32_t body_size;
} pgp_packet_header, pgp_subpacket_header;

typedef struct _pgp_unknown_packet
{
	struct _pgp_packet_header header;
	void *data;
} pgp_unknown_packet, pgp_unknown_subpacket;

typedef struct _pgp_compressed_packet
{
	pgp_packet_header header;

	byte_t compression_algorithm_id;
	void *data;
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

} pgp_literal_data_format;

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
	byte_t user_data[1];
} pgp_user_id_packet;

typedef enum _pgp_user_attribute_subpacket_type
{
	PGP_USER_ATTRIBUTE_IMAGE = 1,
	PGP_USER_ATTRIBUTE_UID = 2
} pgp_user_attribute_subpacket_type;

typedef enum _pgp_user_attribute_image_encoding
{
	PGP_USER_ATTRIBUTE_IMAGE_JPEG = 1
} pgp_user_attribute_image_encoding;

typedef struct _pgp_user_attribute_image_subpacket
{
	pgp_subpacket_header header;

	uint16_t image_header_size;  // 1
	byte_t image_header_version; // 1
	byte_t image_encoding;
	byte_t reserved[12]; // 12 zero octets

	void *image_data;

} pgp_user_attribute_image_subpacket;

typedef struct _pgp_user_attribute_uid_subpacket
{
	pgp_subpacket_header header;
	byte_t user_data[1];
} pgp_user_attribute_uid_subpacket;

typedef struct _pgp_user_attribute_packet
{
	pgp_packet_header header;
	pgp_stream_t *subpackets;
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

typedef struct _pgp_keyring_packet
{
	pgp_packet_header header;

	byte_t trust_level;
	byte_t fingerprint_size;

	byte_t primary_fingerprint[32];

	byte_t subkey_count;
	void *subkey_fingerprints;

	byte_t uid_count;
	uint32_t uid_size;
	void *uids;

} pgp_keyring_packet;

#define PGP_PACKET_HEADER_FORMAT(T) (((T) & 0xC0) == 0xC0 ? PGP_HEADER : PGP_LEGACY_HEADER)

#define PGP_WRITE_ARMOR           0x1
#define PGP_WRITE_ARMOR_NO_CRC    0x2
#define PGP_WRITE_ARMOR_FORCE_CRC 0x4

#define PGP_PRINT_HEADER_ONLY 0x1
#define PGP_PRINT_MPI_MINIMAL 0x2

pgp_packet_header pgp_packet_header_read(void *data, size_t size);
uint32_t pgp_packet_header_write(pgp_packet_header *header, void *ptr);
uint32_t pgp_packet_header_print(pgp_packet_header *header, void *str, size_t size);

pgp_subpacket_header pgp_subpacket_header_read(void *data, size_t size);
uint32_t pgp_subpacket_header_write(pgp_subpacket_header *header, void *ptr);

pgp_packet_header pgp_encode_packet_header(pgp_packet_header_format header_format, pgp_packet_type packet_type, uint32_t body_size);
pgp_subpacket_header pgp_encode_subpacket_header(byte_t type, byte_t set_critical, uint32_t body_size);

byte_t pgp_packet_validate_tag(byte_t tag);
byte_t pgp_packet_tag(pgp_packet_header_format header_type, pgp_packet_type packet_type, uint32_t size);
pgp_packet_type pgp_packet_get_type(byte_t tag);

uint32_t pgp_subpacket_stream_octets(pgp_stream_t *stream);

void *pgp_packet_read(void *data, size_t size);
size_t pgp_packet_write(void *packet, void *ptr, size_t size);
size_t pgp_packet_print(void *packet, void *str, size_t size, uint32_t options);

void pgp_packet_delete(void *packet);

// Compressed Packet (Tag 8)
pgp_compresed_packet *pgp_compressed_packet_new(byte_t header_format, byte_t compression_algorithm_id);
void pgp_compressed_packet_delete(pgp_compresed_packet *packet);

pgp_compresed_packet *pgp_compressed_packet_set_data(pgp_compresed_packet *packet, void *ptr, size_t size);
size_t pgp_compressed_packet_get_data(pgp_compresed_packet *packet, void *ptr, size_t size);
size_t pgp_compressed_packet_get_raw_data(pgp_compresed_packet *packet, void *ptr, size_t size);

pgp_compresed_packet *pgp_compressed_packet_read(void *data, size_t size);
size_t pgp_compressed_packet_write(pgp_compresed_packet *packet, void *ptr, size_t size);
size_t pgp_compressed_packet_print(pgp_compresed_packet *packet, void *str, size_t size);

// Marker Packet (Tag 10)
pgp_marker_packet *pgp_marker_packet_new(byte_t header_format);
void pgp_marker_packet_delete(pgp_marker_packet *packet);

pgp_marker_packet *pgp_marker_packet_read(void *data, size_t size);
size_t pgp_marker_packet_write(pgp_marker_packet *packet, void *ptr, size_t size);
size_t pgp_marker_packet_print(pgp_marker_packet *packet, void *str, size_t size);

// Literal Data Packet (Tag 11)
pgp_literal_packet *pgp_literal_packet_new(byte_t header_format);
void pgp_literal_packet_delete(pgp_literal_packet *packet);

size_t pgp_literal_packet_get_filename(pgp_literal_packet *packet, void *filename, size_t size);
pgp_literal_packet *pgp_literal_packet_set_filename(pgp_literal_packet *packet, void *filename, size_t size);

size_t pgp_literal_packet_get_data(pgp_literal_packet *packet, void *data, size_t size);
pgp_literal_packet *pgp_literal_packet_set_data(pgp_literal_packet *packet, pgp_literal_data_format format, uint32_t date, void *data,
												size_t size);

pgp_literal_packet *pgp_literal_packet_read(void *data, size_t size);
size_t pgp_literal_packet_write(pgp_literal_packet *packet, void *ptr, size_t size);
size_t pgp_literal_packet_print(pgp_literal_packet *packet, void *str, size_t size);

// User ID Packet (Tag 13)
pgp_user_id_packet *pgp_user_id_packet_new(byte_t header_format, void *user_name, uint16_t user_name_size, void *user_comment,
										   uint16_t user_comment_size, void *user_email, uint16_t user_email_size);
void pgp_user_id_packet_delete(pgp_user_id_packet *packet);

pgp_user_id_packet *pgp_user_id_packet_read(void *data, size_t size);
size_t pgp_user_id_packet_write(pgp_user_id_packet *packet, void *ptr, size_t size);
size_t pgp_user_id_packet_print(pgp_user_id_packet *packet, void *str, size_t size);

// User Attribute Packet (Tag 17)
pgp_user_attribute_packet *pgp_user_attribute_packet_new(byte_t header_format);
void pgp_user_attribute_packet_delete(pgp_user_attribute_packet *packet);

size_t pgp_user_attribute_packet_get_image(pgp_user_attribute_packet *packet, void *image, size_t size);
pgp_user_attribute_packet *pgp_user_attribute_packet_set_image(pgp_user_attribute_packet *packet, byte_t format, void *image, size_t size);

size_t pgp_user_attribute_packet_get_uid(pgp_user_attribute_packet *packet, void *data, size_t size);
pgp_user_attribute_packet *pgp_user_attribute_packet_set_uid(pgp_user_attribute_packet *packet, void *user_name, uint16_t user_name_size,
															 void *user_comment, uint16_t user_comment_size, void *user_email,
															 uint16_t user_email_size);

pgp_user_attribute_packet *pgp_user_attribute_packet_read(void *data, size_t size);
size_t pgp_user_attribute_packet_write(pgp_user_attribute_packet *packet, void *ptr, size_t size);
size_t pgp_user_attribute_packet_print(pgp_user_attribute_packet *packet, void *str, size_t size);

// Padding Packet (Tag 21)
pgp_padding_packet *pgp_padding_packet_new(byte_t header_format, void *data, size_t size);
void pgp_padding_packet_delete(pgp_padding_packet *packet);

pgp_padding_packet *pgp_padding_packet_read(void *data, size_t size);
size_t pgp_padding_packet_write(pgp_padding_packet *packet, void *ptr, size_t size);
size_t pgp_padding_packet_print(pgp_padding_packet *packet, void *str, size_t size);

// Modification Detection Code Packet (Tag 19)
pgp_mdc_packet *pgp_mdc_packet_new(byte_t header_format);
void pgp_mdc_packet_delete(pgp_mdc_packet *packet);

void pgp_mdc_packet_get_hash(pgp_mdc_packet *packet, byte_t hash[20]);
void pgp_mdc_packet_set_hash(pgp_mdc_packet *packet, byte_t hash[20]);

pgp_mdc_packet *pgp_mdc_packet_read(void *data, size_t size);
size_t pgp_mdc_packet_write(pgp_mdc_packet *packet, void *ptr, size_t size);
size_t pgp_mdc_packet_print(pgp_mdc_packet *packet, void *str, size_t size);

// Trust Packet (Tag 12)
pgp_trust_packet *pgp_trust_packet_new(byte_t header_format, byte_t trust_level);
void pgp_trust_packet_delete(pgp_trust_packet *packet);

pgp_trust_packet *pgp_trust_packet_read(void *data, size_t size);
size_t pgp_trust_packet_write(pgp_trust_packet *packet, void *ptr, size_t size);
size_t pgp_trust_packet_print(pgp_trust_packet *packet, void *str, size_t size);

// Keyring Packet
pgp_keyring_packet *pgp_keyring_packet_new(byte_t trust_level);
void pgp_keyring_packet_delete(pgp_keyring_packet *packet);

pgp_keyring_packet *pgp_keyring_packet_read(void *data, size_t size);
size_t pgp_keyring_packet_write(pgp_keyring_packet *packet, void *ptr, size_t size);
size_t pgp_keyring_packet_print(pgp_keyring_packet *packet, void *str, size_t size);

// Unknown Packet
pgp_unknown_packet *pgp_unknown_packet_read(void *data, size_t size);
size_t pgp_unknown_packet_write(pgp_unknown_packet *packet, void *ptr, size_t size);
size_t pgp_unknown_packet_print(pgp_unknown_packet *packet, void *str, size_t size);

#endif
