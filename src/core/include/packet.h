/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_PACKET_H
#define SPGP_PACKET_H

#include <pgp.h>
#include <error.h>
#include <stream.h>

// Refer RFC 9580 - OpenPGP, Section 5 Packet Types

#define PGP_MAX_SPLIT_SIZE   30
#define PGP_SPLIT_SIZE(size) ((uint32_t)1 << (size))

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
	PGP_UNKNOWN_HEADER = 0,
	PGP_LEGACY_HEADER = 1,
	PGP_HEADER = 2
} pgp_packet_header_format;

typedef struct _pgp_packet_header
{
	byte_t tag;
	byte_t header_size;
	byte_t critical;

	union
	{
		struct
		{
			byte_t partial_begin : 1;
			byte_t partial_continue : 1;
			byte_t partial_end : 1;
			byte_t partial_legacy : 1;
		};

		byte_t partial;
	};

	size_t body_size;
} pgp_packet_header, pgp_subpacket_header, pgp_partial_header;

typedef struct _pgp_partial_packet
{
	pgp_partial_header header;
	void *data;
} pgp_partial_packet;

typedef struct _pgp_unknown_packet
{
	struct _pgp_packet_header header;
	void *data;
} pgp_unknown_packet, pgp_unknown_subpacket;

typedef struct _pgp_data_packet
{
	pgp_packet_header header;
	pgp_stream_t *partials;

	size_t data_size;
	void *data;

} pgp_data_packet;

typedef struct _pgp_compressed_packet
{
	pgp_packet_header header;
	pgp_stream_t *partials;

	size_t data_size;
	void *data;

	byte_t compression_algorithm_id;

} pgp_compresed_packet;

typedef struct _pgp_marker_packet
{
	pgp_packet_header header;
	byte_t marker[3]; // "PGP" (0x50, 0x47, 0x50)
} pgp_marker_packet;

typedef enum _pgp_literal_data_format
{
	PGP_LITERAL_DATA_BINARY = 0x62, // 'b'
	PGP_LITERAL_DATA_LOCAL = 0x6C,  // 'l'
	PGP_LITERAL_DATA_MIME = 0x6D,   // 'm'
	PGP_LITERAL_DATA_TEXT = 0x74,   // 't'
	PGP_LITERAL_DATA_UTF8 = 0x75    // 'u',

} pgp_literal_data_format;

typedef struct _pgp_literal_packet
{
	pgp_packet_header header;
	pgp_stream_t *partials;

	size_t data_size;
	void *data;

	byte_t format;
	uint32_t date;

	byte_t filename_size;
	void *filename;

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

	uint32_t subpacket_octets;
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
	PGP_TRUST_MARGINAL = 1,
	PGP_TRUST_FULL = 2,
	PGP_TRUST_ULTIMATE = 3,
} pgp_trust_level;

typedef struct _pgp_trust_packet
{
	pgp_packet_header header;
	byte_t level;
} pgp_trust_packet;

typedef struct _pgp_keyring_packet
{
	pgp_packet_header header;

	byte_t key_version;
	byte_t fingerprint_size;
	byte_t primary_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE];

	uint16_t subkey_count;
	uint32_t subkey_size;
	uint32_t subkey_capacity;
	void *subkey_fingerprints;

	uint32_t user_size;
	pgp_stream_t *users;

} pgp_keyring_packet;

typedef struct _pgp_user_info
{
	uint32_t info_octets;

	uint32_t uid_octets;
	uint32_t server_octets;

	byte_t trust;
	byte_t features;
	byte_t flags;

	byte_t fingerprint_size;
	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE];

	byte_t hash_algorithm_preferences_octets;
	byte_t cipher_algorithm_preferences_octets;
	byte_t compression_algorithm_preferences_octets;
	byte_t cipher_modes_preferences_octets;
	byte_t aead_algorithm_preferences_octets;

	void *uid;
	void *server;

	byte_t hash_algorithm_preferences[16];
	byte_t cipher_algorithm_preferences[16];
	byte_t compression_algorithm_preferences[4];
	byte_t cipher_modes_preferences[4];
	byte_t aead_algorithm_preferences[32][2];

} pgp_user_info;

typedef struct _pgp_signature_packet pgp_signature_packet;

#define PGP_PACKET_HEADER_FORMAT(T) (((T) & 0xC0) == 0xC0 ? PGP_HEADER : (((T) & 0x80) == 0x80) ? PGP_LEGACY_HEADER : PGP_UNKNOWN_HEADER)
#define PGP_ERROR(H)                ((H).error != PGP_NO_ERROR)

#define PGP_PACKET_OCTETS(H)    ((H).header_size + (H).body_size)
#define PGP_SUBPACKET_OCTETS(H) ((H).header_size + (H).body_size)

#define PGP_WRITE_ARMOR           0x1
#define PGP_WRITE_ARMOR_NO_CRC    0x2
#define PGP_WRITE_ARMOR_FORCE_CRC 0x4

#define PGP_PRINT_HEADER_ONLY 0x1
#define PGP_PRINT_MPI_MINIMAL 0x2

pgp_error_t pgp_packet_header_read(pgp_packet_header *header, void *data, size_t size);
uint32_t pgp_packet_header_write(pgp_packet_header *header, void *ptr);
size_t pgp_packet_header_print(pgp_packet_header *header, void *str, size_t size);

pgp_error_t pgp_subpacket_header_read(pgp_subpacket_header *header, void *data, size_t size);
uint32_t pgp_subpacket_header_write(pgp_subpacket_header *header, void *ptr);

pgp_error_t pgp_partial_header_read(pgp_partial_header *header, void *data, size_t size);
uint32_t pgp_partial_header_write(pgp_partial_header *header, void *ptr);

pgp_packet_header pgp_packet_header_encode(pgp_packet_header_format header_format, pgp_packet_type packet_type, byte_t partial,
										   size_t body_size);
pgp_subpacket_header pgp_subpacket_header_encode(byte_t type, byte_t set_critical, uint32_t body_size);
pgp_partial_header pgp_partial_header_encode(uint32_t body_size);

pgp_packet_type pgp_packet_get_type(byte_t tag);

pgp_error_t pgp_packet_read(void **packet, void *data, size_t size);
size_t pgp_packet_write(void *packet, void *ptr, size_t size);
size_t pgp_packet_print(void *packet, void *str, size_t size, uint32_t options);

void pgp_packet_delete(void *packet);

pgp_error_t pgp_partial_packet_new(pgp_partial_packet **packet, void *data, uint32_t size);
void pgp_partial_packet_delete(pgp_partial_packet *packet);

pgp_error_t pgp_partial_packet_read(void **packet, void *data, size_t size);
size_t pgp_partial_packet_write(pgp_partial_packet *packet, void *ptr, size_t size);
size_t pgp_partial_packet_print(pgp_partial_packet *packet, void *str, size_t size);

pgp_error_t pgp_data_packet_collate(pgp_data_packet *packet);
pgp_error_t pgp_data_packet_split(pgp_data_packet *packet, byte_t split);

// Compressed Packet (Tag 8)
pgp_error_t pgp_compressed_packet_new(pgp_compresed_packet **packet, byte_t header_format, byte_t compression_algorithm_id);
void pgp_compressed_packet_delete(pgp_compresed_packet *packet);

pgp_error_t pgp_compressed_packet_compress(pgp_compresed_packet *packet, pgp_stream_t *stream);
pgp_error_t pgp_compressed_packet_decompress(pgp_compresed_packet *packet, pgp_stream_t **stream);

pgp_error_t pgp_compressed_packet_collate(pgp_compresed_packet *packet);
pgp_error_t pgp_compressed_packet_split(pgp_compresed_packet *packet, byte_t split);

pgp_error_t pgp_compressed_packet_read(pgp_compresed_packet **packet, void *data, size_t size);
size_t pgp_compressed_packet_write(pgp_compresed_packet *packet, void *ptr, size_t size);
size_t pgp_compressed_packet_print(pgp_compresed_packet *packet, void *str, size_t size);

// Marker Packet (Tag 10)
pgp_error_t pgp_marker_packet_new(pgp_marker_packet **packet, byte_t header_format);
void pgp_marker_packet_delete(pgp_marker_packet *packet);

pgp_error_t pgp_marker_packet_read(pgp_marker_packet **packet, void *data, size_t size);
size_t pgp_marker_packet_write(pgp_marker_packet *packet, void *ptr, size_t size);
size_t pgp_marker_packet_print(pgp_marker_packet *packet, void *str, size_t size);

// Literal Data Packet (Tag 11)
pgp_error_t pgp_literal_packet_new(pgp_literal_packet **packet, byte_t header_format, uint32_t date, void *filename, byte_t filename_size);
void pgp_literal_packet_delete(pgp_literal_packet *packet);

pgp_error_t pgp_literal_packet_store(pgp_literal_packet *packet, pgp_literal_data_format format, void *data, size_t size);
pgp_error_t pgp_literal_packet_retrieve(pgp_literal_packet *packet, void *data, size_t size);

pgp_error_t pgp_literal_packet_collate(pgp_literal_packet *packet);
pgp_error_t pgp_literal_packet_split(pgp_literal_packet *packet, byte_t split);

pgp_error_t pgp_literal_packet_read(pgp_literal_packet **packet, void *data, size_t size);
size_t pgp_literal_packet_write(pgp_literal_packet *packet, void *ptr, size_t size);
size_t pgp_literal_packet_print(pgp_literal_packet *packet, void *str, size_t size);

// User ID Packet (Tag 13)
uint32_t pgp_user_id_generate(void *buffer, uint32_t size, void *user_name, uint16_t user_name_size, void *user_comment,
							  uint16_t user_comment_size, void *user_email, uint16_t user_email_size);

pgp_error_t pgp_user_id_packet_new(pgp_user_id_packet **packet, byte_t header_format, void *user, uint16_t user_size);
void pgp_user_id_packet_delete(pgp_user_id_packet *packet);

pgp_error_t pgp_user_id_packet_read(pgp_user_id_packet **packet, void *data, size_t size);
size_t pgp_user_id_packet_write(pgp_user_id_packet *packet, void *ptr, size_t size);
size_t pgp_user_id_packet_print(pgp_user_id_packet *packet, void *str, size_t size);

// User Attribute Packet (Tag 17)
pgp_error_t pgp_user_attribute_packet_new(pgp_user_attribute_packet **packet);
void pgp_user_attribute_packet_delete(pgp_user_attribute_packet *packet);

pgp_error_t pgp_user_attribute_packet_get_image(pgp_user_attribute_packet *packet, void *image, size_t *size);
pgp_error_t pgp_user_attribute_packet_set_image(pgp_user_attribute_packet *packet, byte_t format, void *image, size_t size);

pgp_error_t pgp_user_attribute_packet_get_uid(pgp_user_attribute_packet *packet, void *data, size_t *size);
pgp_error_t pgp_user_attribute_packet_set_uid(pgp_user_attribute_packet *packet, void *user, size_t size);

pgp_error_t pgp_user_attribute_packet_read(pgp_user_attribute_packet **packet, void *data, size_t size);
size_t pgp_user_attribute_packet_write(pgp_user_attribute_packet *packet, void *ptr, size_t size);
size_t pgp_user_attribute_packet_print(pgp_user_attribute_packet *packet, void *str, size_t size);

// Padding Packet (Tag 21)
pgp_error_t pgp_padding_packet_new(pgp_padding_packet **packet, void *data, uint32_t size);
void pgp_padding_packet_delete(pgp_padding_packet *packet);

pgp_error_t pgp_padding_packet_read(pgp_padding_packet **packet, void *data, size_t size);
size_t pgp_padding_packet_write(pgp_padding_packet *packet, void *ptr, size_t size);
size_t pgp_padding_packet_print(pgp_padding_packet *packet, void *str, size_t size);

// Modification Detection Code Packet (Tag 19)
pgp_error_t pgp_mdc_packet_new(pgp_mdc_packet **packet, byte_t hash[20]);
void pgp_mdc_packet_delete(pgp_mdc_packet *packet);

pgp_error_t pgp_mdc_packet_read(pgp_mdc_packet **packet, void *data, size_t size);
size_t pgp_mdc_packet_write(pgp_mdc_packet *packet, void *ptr, size_t size);
size_t pgp_mdc_packet_print(pgp_mdc_packet *packet, void *str, size_t size);

// Trust Packet (Tag 12)
pgp_error_t pgp_trust_packet_new(pgp_trust_packet **packet, byte_t header_format, byte_t trust_level);
void pgp_trust_packet_delete(pgp_trust_packet *packet);

pgp_error_t pgp_trust_packet_read(pgp_trust_packet **packet, void *data, size_t size);
size_t pgp_trust_packet_write(pgp_trust_packet *packet, void *ptr, size_t size);
size_t pgp_trust_packet_print(pgp_trust_packet *packet, void *str, size_t size);

// Keyring Packet
pgp_error_t pgp_keyring_packet_new(pgp_keyring_packet **packet, byte_t key_version,
								   byte_t primary_key_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], pgp_user_info *user);
void pgp_keyring_packet_delete(pgp_keyring_packet *packet);

pgp_error_t pgp_keyring_packet_add_user(pgp_keyring_packet *packet, pgp_user_info *user);
void pgp_keyring_packet_remove_user(pgp_keyring_packet *packet, byte_t *uid, uint32_t uid_size);

pgp_error_t pgp_keyring_packet_add_subkey(pgp_keyring_packet *packet, byte_t subkey[PGP_KEY_MAX_FINGERPRINT_SIZE]);
void pgp_keyring_packet_remove_subkey(pgp_keyring_packet *packet, byte_t subkey[PGP_KEY_MAX_FINGERPRINT_SIZE]);

pgp_user_info *pgp_keyring_packet_search(pgp_keyring_packet *packet, void *input, uint32_t size);

pgp_error_t pgp_keyring_packet_read(pgp_keyring_packet **packet, void *data, size_t size);
size_t pgp_keyring_packet_write(pgp_keyring_packet *packet, void *ptr, size_t size);
size_t pgp_keyring_packet_print(pgp_keyring_packet *packet, void *str, size_t size);

// Unknown Packet
pgp_error_t pgp_unknown_packet_read(pgp_unknown_packet **packet, void *data, size_t size);
size_t pgp_unknown_packet_write(pgp_unknown_packet *packet, void *ptr, size_t size);
size_t pgp_unknown_packet_print(pgp_unknown_packet *packet, void *str, size_t size);

// User Info
pgp_error_t pgp_user_info_new(pgp_user_info **info, void *uid, uint32_t uid_size, void *server, uint32_t server_size, byte_t trust,
							  byte_t features, byte_t flags);
void pgp_user_info_delete(pgp_user_info *user);

pgp_error_t pgp_user_info_from_certificate(pgp_user_info **info, pgp_user_id_packet *user, pgp_signature_packet *sign);

pgp_error_t pgp_user_info_set_hash_preferences(pgp_user_info *user, byte_t count, byte_t preferences[]);
pgp_error_t pgp_user_info_set_cipher_preferences(pgp_user_info *user, byte_t count, byte_t preferences[]);
pgp_error_t pgp_user_info_set_compression_preferences(pgp_user_info *user, byte_t count, byte_t preferences[]);
pgp_error_t pgp_user_info_set_mode_preferences(pgp_user_info *user, byte_t count, byte_t preferences[]);
pgp_error_t pgp_user_info_set_aead_preferences(pgp_user_info *user, byte_t count, byte_t preferences[][2]);

#endif
