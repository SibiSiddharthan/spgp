/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_SIGNATURE_H
#define SPGP_SIGNATURE_H

#include <spgp.h>
#include <packet.h>
#include <stream.h>
#include <key.h>
#include <mpi.h>

// Refer RFC 9580 - OpenPGP, Section 5.2 Signature Packet

typedef enum _pgp_signature_version
{
	PGP_SIGNATURE_V3 = 3,
	PGP_SIGNATURE_V4 = 4,
	PGP_SIGNATURE_V5 = 5,
	PGP_SIGNATURE_V6 = 6
} pgp_signature_version;

typedef enum _pgp_one_pass_signature_version
{
	PGP_ONE_PASS_SIGNATURE_V3 = 3,
	PGP_ONE_PASS_SIGNATURE_V6 = 6
} pgp_one_pass_signature_version;

typedef enum _pgp_signature_type
{
	PGP_BINARY_SIGNATURE = 0x00,
	PGP_TEXT_SIGNATURE = 0x01,
	PGP_STANDALONE_SIGNATURE = 0x02,
	PGP_GENERIC_CERTIFICATION_SIGNATURE = 0x10,
	PGP_PERSONA_CERTIFICATION_SIGNATURE = 0x11,
	PGP_CASUAL_CERTIFICATION_SIGNATURE = 0x12,
	PGP_POSITIVE_CERTIFICATION_SIGNATURE = 0x13,
	PGP_ATTESTED_KEY_SIGNATURE = 0x16,
	PGP_SUBKEY_BINDING_SIGNATURE = 0x18,
	PGP_PRIMARY_KEY_BINDING_SIGNATURE = 0x19,
	PGP_DIRECT_KEY_SIGNATURE = 0x1F,
	PGP_KEY_REVOCATION_SIGNATURE = 0x20,
	PGP_SUBKEY_REVOCATION_SIGNATURE = 0x28,
	PGP_CERTIFICATION_REVOCATION_SIGNATURE = 0x30,
	PGP_TIMESTAMP_SIGNATURE = 0x40,
	PGP_THIRD_PARTY_CONFIRMATION_SIGNATURE = 0x50,
	PGP_RESERVED_SIGNATURE = 0xFF
} pgp_signature_type;

typedef enum _pgp_signature_subpacket_type
{
	PGP_SIGNATURE_CREATION_TIME_SUBPACKET = 2,
	PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET = 3,
	PGP_EXPORTABLE_SUBPACKET = 4,
	PGP_TRUST_SIGNATURE_SUBPACKET = 5,
	PGP_REGULAR_EXPRESSION_SUBPACKET = 6,
	PGP_REVOCABLE_SUBPACKET = 7,
	PGP_KEY_EXPIRATION_TIME_SUBPACKET = 9,
	PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET = 11,
	PGP_REVOCATION_KEY_SUBPACKET = 12, // Deprecated
	PGP_ISSUER_KEY_ID_SUBPACKET = 16,
	PGP_NOTATION_DATA_SUBPACKET = 20,
	PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET = 21,
	PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET = 22,
	PGP_KEY_SERVER_PREFERENCES_SUBPACKET = 23,
	PGP_PREFERRED_KEY_SERVER_SUBPACKET = 24,
	PGP_PRIMARY_USER_ID_SUBPACKET = 25,
	PGP_POLICY_URI_SUBPACKET = 26,
	PGP_KEY_FLAGS_SUBPACKET = 27,
	PGP_SIGNER_USER_ID_SUBPACKET = 28,
	PGP_REASON_FOR_REVOCATION_SUBPACKET = 29,
	PGP_FEATURES_SUBPACKET = 30,
	PGP_SIGNATURE_TARGET_SUBPACKET = 31,
	PGP_EMBEDDED_SIGNATURE_SUBPACKET = 32,
	PGP_ISSUER_FINGERPRINT_SUBPACKET = 33,
	PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET = 34, // Deprecated
	PGP_RECIPIENT_FINGERPRINT_SUBPACKET = 35,
	PGP_ATTESTED_CERTIFICATIONS_SUBPACKET = 37,
	PGP_KEY_BLOCK_SUBPACKET = 38,
	PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET = 39,
	PGP_LITERAL_DATA_META_HASH_SUBPACKET = 40,
	PGP_TRUST_ALIAS_SUBPACKET = 41
} pgp_signature_subpacket_type;

typedef enum _pgp_revocation_code
{
	PGP_REVOCATION_NO_REASON = 0,       // No reason specified
	PGP_REVOCATION_KEY_SUPERSEDED = 1,  // Key is superseded
	PGP_REVOCATION_KEY_COMPROMISED = 2, // Key material has been compromised
	PGP_REVOCATION_KEY_RETIRED = 3,     // Key is retired and no longer used
	PGP_REVOCATION_USER_ID_INVALID = 32 // User ID information is no longer valid
} pgp_revocation_code;

// Subpacket flags
#define PGP_KEY_SERVER_NO_MODIFY 0x80       // The key can only be modified by the keyholder or an administrator of the key server
#define PGP_NOTATION_DATA_UTF8   0x80000000 // Notation value is UTF-8 text

// Key flags
#define PGP_KEY_FLAG_CERTIFY         0x01 // This key may be used to make User ID certifications or Direct Key signatures over other keys
#define PGP_KEY_FLAG_SIGN            0x02 // This key may be used to sign data
#define PGP_KEY_FLAG_ENCRYPT_COM     0x04 // This key may be used to encrypt communications
#define PGP_KEY_FLAG_ENCRYPT_STORAGE 0x08 // This key may be used to encrypt storage
#define PGP_KEY_FLAG_PRIVATE_SPLIT   0x10 // The private component of this key may have been split by a secret-sharing mechanism
#define PGP_KEY_FLAG_AUTHENTICATION  0x20 // This key may be used for authentication
#define PGP_KEY_FLAG_PRIVATE_SHARED  0x80 // The private component of this key may be in the possession of more than one person

// Feature flags
#define PGP_FEATURE_SEIPD_V1 0x01 // Version 1 Symmetrically Encrypted and Integrity Protected Data packet
#define PGP_FEATURE_SEIPD_V2 0x08 // Version 2 Symmetrically Encrypted and Integrity Protected Data packet

// Revocation class
#define PGP_REVOCATION_CLASS_SENSITIVE 0x40
#define PGP_REVOCATION_CLASS_NORMAL    0x80

typedef struct _pgp_signature_packet
{
	pgp_packet_header header;

	byte_t version;
	byte_t type;
	uint32_t timestamp;
	byte_t public_key_algorithm_id;
	byte_t hash_algorithm_id;
	byte_t key_id[8];
	byte_t quick_hash[2];

	byte_t salt_size;
	byte_t salt[32];

	uint32_t hashed_octets;
	uint32_t unhashed_octets;

	pgp_stream_t *hashed_subpackets;
	pgp_stream_t *unhashed_subpackets;

	uint32_t signature_size;
	void *signature;
} pgp_signature_packet;

typedef struct _pgp_one_pass_signature_packet
{
	pgp_packet_header header;

	byte_t version;
	byte_t type;
	byte_t nested;
	byte_t public_key_algorithm_id;
	byte_t hash_algorithm_id;

	union
	{
		byte_t key_id[8];
		byte_t key_fingerprint[32];
	};

	byte_t salt_size;
	byte_t salt[32];

} pgp_one_pass_signature_packet;

// Signature subpackets

typedef struct _pgp_timestamp_subpacket
{
	pgp_subpacket_header header;
	uint32_t time;
} pgp_signature_creation_time_subpacket, pgp_signature_expiry_time_subpacket, pgp_key_expiration_time_subpacket;

typedef struct _pgp_boolean_subpacket
{
	pgp_subpacket_header header;
	byte_t state : 1; // 1 for yes, 0 for no.
} pgp_exportable_subpacket, pgp_revocable_subpacket, pgp_primary_user_id_subpacket;

typedef struct _pgp_preferred_algorithm_subpacket
{
	pgp_subpacket_header header;
	byte_t preferred_algorithms[1];
} pgp_preferred_symmetric_ciphers_subpacket, pgp_preferred_hash_algorithms_subpacket, pgp_preferred_compression_algorithms_subpacket,
	pgp_preferred_encryption_modes_subpacket, pgp_preferred_aead_ciphersuites_subpacket;

typedef struct _pgp_flags_subpacket
{
	pgp_subpacket_header header;
	byte_t flags[1];
} pgp_key_server_preferences_subpacket, pgp_key_flags_subpacket, pgp_features_subpacket;

typedef struct _pgp_string_subpacket
{
	pgp_subpacket_header header;

	union
	{
		void *data;
		void *regex;  // pgp_regular_expression_subpacket
		void *server; // pgp_preferred_key_server_subpacket
		void *policy; // pgp_policy_uri_subpacket
		void *uid;    // pgp_signer_user_id_subpacket
		void *alias;  // pgp_trust_alias_subpacket
	};
} pgp_regular_expression_subpacket, pgp_preferred_key_server_subpacket, pgp_policy_uri_subpacket, pgp_signer_user_id_subpacket,
	pgp_trust_alias_subpacket;

typedef struct _pgp_key_fingerprint_subpacket
{
	pgp_subpacket_header header;
	pgp_key_version version;
	byte_t fingerprint[32];
} pgp_issuer_fingerprint_subpacket, pgp_recipient_fingerprint_subpacket;

typedef struct _pgp_trust_signature_subpacket
{
	pgp_subpacket_header header;
	byte_t trust_level;
	byte_t trust_amount;
} pgp_trust_signature_subpacket;

typedef struct _pgp_revocation_key_subpacket
{
	pgp_subpacket_header header;
	byte_t revocation_class;
	byte_t algorithm_id;
	byte_t key_fingerprint_v4[20];
} pgp_revocation_key_subpacket;

typedef struct _pgp_issuer_key_id_subpacket
{
	pgp_subpacket_header header;
	byte_t key_id[8];
} pgp_issuer_key_id_subpacket;

typedef struct _pgp_notation_data_subpacket
{
	pgp_subpacket_header header;
	uint32_t flags;
	uint16_t name_size;
	uint16_t value_size;
	void *data;
} pgp_notation_data_subpacket;

typedef struct _reason_for_revocation_subpacket
{
	pgp_subpacket_header header;
	byte_t code;
	byte_t *reason;
} pgp_reason_for_revocation_subpacket;

typedef struct _pgp_signature_target_subpacket
{
	pgp_subpacket_header header;
	byte_t public_key_algorithm_id;
	byte_t hash_algorithm_id;
	byte_t hash[1];
} pgp_signature_target_subpacket;

typedef pgp_signature_packet pgp_embedded_signature_subpacket;

typedef struct _pgp_attested_certifications_subpacket
{
	pgp_subpacket_header header;
	uint16_t count;
	void *hash;
} pgp_attested_certifications_subpacket;

typedef struct _pgp_literal_data_meta_hash_subpacket
{
	pgp_subpacket_header header;
	byte_t octet; // 0
	byte_t hash[32];
} pgp_literal_data_meta_hash_subpacket;

typedef struct _pgp_rsa_signature
{
	mpi_t *e;
} pgp_rsa_signature;

typedef struct _pgp_dsa_signature
{
	mpi_t *r, *s;
} pgp_dsa_signature, pgp_ecdsa_signature, pgp_eddsa_signature;

typedef struct _pgp_ed25519_signature
{
	byte_t sig[64];
} pgp_ed25519_signature;

typedef struct _pgp_ed448_signature
{
	byte_t sig[114];
} pgp_ed448_signature;

pgp_signature_packet *pgp_signature_packet_new(byte_t version, byte_t type, byte_t public_key_algorithm_id, byte_t hash_algorithm_id);
void pgp_signature_packet_delete(pgp_signature_packet *packet);

uint32_t pgp_signature_packet_sign(pgp_signature_packet *packet, pgp_key_packet *key, void *data, size_t size);
uint32_t pgp_signature_packet_verify(pgp_signature_packet *packet, pgp_key_packet *key, void *data, size_t size);

pgp_signature_packet *pgp_signature_packet_read(void *data, size_t size);
size_t pgp_signature_packet_write(pgp_signature_packet *packet, void *ptr, size_t size);
size_t pgp_signature_packet_print(pgp_signature_packet *packet, void *ptr, size_t size, uint32_t options);

pgp_one_pass_signature_packet *pgp_one_pass_signature_packet_new(byte_t version, byte_t type, byte_t nested, byte_t public_key_algorithm_id,
																 byte_t hash_algorithm_id, void *salt, byte_t salt_size,
																 void *key_fingerprint, byte_t key_fingerprint_size);
void pgp_one_pass_signature_packet_delete(pgp_one_pass_signature_packet *packet);

pgp_one_pass_signature_packet *pgp_one_pass_signature_packet_read(void *data, size_t size);
size_t pgp_one_pass_signature_packet_write(pgp_one_pass_signature_packet *packet, void *ptr, size_t size);
size_t pgp_one_pass_signature_packet_print(pgp_one_pass_signature_packet *packet, void *ptr, size_t size);

pgp_rsa_signature *pgp_rsa_signature_new(uint16_t bits);
void pgp_rsa_signature_delete(pgp_rsa_signature *sign);

pgp_dsa_signature *pgp_dsa_signature_new(uint16_t bits);
void pgp_dsa_signature_delete(pgp_dsa_signature *sign);

#endif
