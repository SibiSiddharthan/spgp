/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <signature.h>

#include <string.h>

uint32_t get_signature_size(pgp_public_key_algorithms algorithm);
uint32_t get_header_size(pgp_packet_header_type type, size_t size);
uint32_t pgp_packet_header_write(pgp_packet_header *header, void *ptr);
uint32_t pgp_signature_data_write(pgp_public_key_algorithms algorithm, void *data, void *ptr);

static uint32_t pgp_signature_subpacket_write(void *data, size_t size, void *ptr)
{
	pgp_signature_subpacket_header *header = data;
	byte_t *out = ptr;
	uint32_t pos = 0;

	if (size == 0)
	{
		return 0;
	}

	while (1)
	{
		switch (header->type)
		{
		case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
		case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
		case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
			break;
		case PGP_EXPORTABLE_SUBPACKET:
		case PGP_REVOCABLE_SUBPACKET:
		case PGP_PRIMARY_USER_ID_SUBPACKET:
			break;
		case PGP_KEY_SERVER_REFERENCES_SUBPACKET:
		case PGP_KEY_FLAGS_SUBPACKET:
		case PGP_FEATURES_SUBPACKET:
			break;
		case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
		case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
		case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
		case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
			break;
		case PGP_TRUST_SIGNATURE_SUBPACKET:
			break;
		case PGP_REGULAR_EXPRESSION_SUBPACKET:
			break;
		case PGP_REVOCATION_KEY_SUBPACKET:
			break;
		case PGP_ISSUER_KEY_ID_SUBPACKET:
			break;
		case PGP_NOTATION_DATA_SUBPACKET:
			break;
		case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
			break;
		case PGP_POLICY_URI_SUBPACKET:
			break;
		case PGP_SIGNER_USER_ID_SUBPACKET:
			break;
		case PGP_REASON_FOR_REVOCATION_SUBPACKET:
			break;
		case PGP_SIGNATURE_TARGET_SUBPACKET:
			break;
		case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
			break;
		case PGP_ISSUER_FINGERPRINT_SUBPACKET:
			break;
		case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
			break;
		default:
		{
			// Unrecognized critical subpacket.
			if (header->critical)
			{
				return 0;
			}
		}
		}

		header = (pgp_signature_subpacket_header *)((byte_t *)header + header->size);
	}

	return pos;
}

static uint32_t pgp_signature_packet_v3_write(pgp_signature_packet *packet, void *ptr, uint32_t size)
{
	byte_t *out = ptr;
	uint32_t required_size = 0;
	uint32_t pos = 0;

	// A 1-octet version number with value 3.
	// A 1-octet length of the following hashed material; it be 5:
	// A 1-octet Signature Type ID.
	// A 4-octet creation time.
	// An 8-octet Key ID of the signer.
	// A 1-octet public key algorithm.
	// A 1-octet hash algorithm.
	// A 2-octet field holding left 16 bits of the signed hash value.
	// One or more MPIs comprising the signature

	required_size = 1 + 1 + 1 + 4 + 8 + 1 + 1 + 2 + get_signature_size(packet->public_key_algorithm_id);
	required_size += get_header_size(PGP_LEGACY_HEADER, required_size);

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 1 octet hashed length
	LOAD_8(out + pos, &packet->hashed_size);
	pos += 1;

	// 1 octet signature type
	LOAD_8(out + pos, &packet->type);
	pos += 1;

	// 4 octet timestamp
	uint32_t timestamp = BSWAP_32(packet->timestamp);
	LOAD_32(out + pos, &timestamp);
	pos += 4;

	// 8 octet key-id
	LOAD_64(out + pos, &packet->key_id);
	pos += 8;

	// 1 octet public-key algorithm
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	// 1 octet hash algorithm
	LOAD_8(out + pos, &packet->hash_algorithm_id);
	pos += 1;

	// 2 octets of the left 16 bits of signed hash value
	LOAD_16(out + pos, &packet->quick_hash);
	pos += 2;

	// Signature data
	pos += pgp_signature_data_write(packet->public_key_algorithm_id, packet->signature, out + pos);

	return pos;
}

static uint32_t pgp_signature_packet_v4_v6_write(pgp_signature_packet *packet, void *ptr, uint32_t size)
{
	byte_t *out = ptr;
	uint32_t required_size = 0;
	uint32_t pos = 0;

	// A 1-octet version number. This is 4 for version 4 signatures and 6 for version 6 signatures.
	// A 1-octet Signature Type ID.
	// A 1-octet public key algorithm.
	// A 1-octet hash algorithm.
	// A 2-octet/4-octet count for the hashed subpacket data that follows this field.
	// A hashed subpacket data set (zero or more subpackets).
	// A 2-octet/4-octet count for the unhashed subpacket data that follows this field.
	// An uhashed subpacket data set (zero or more subpackets).
	// A 2-octet field holding the left 16 bits of the signed hash value.
	// (For V6) A 1-octet salt size.
	// (For V6) The salt.
	// One or more MPIs comprising the signature.

	required_size = 1 + 1 + 1 + 1 + 2 + packet->hashed_size + packet->unhashed_size + get_signature_size(packet->public_key_algorithm_id);
	required_size += (packet->version == PGP_SIGNATURE_V6) ? (4 + 4 + 1 + packet->salt_size) : (2 + 2);
	required_size += get_header_size(PGP_HEADER, required_size);

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 1 octet signature type
	LOAD_8(out + pos, &packet->type);
	pos += 1;

	// 1 octet public-key algorithm
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	// 1 octet hash algorithm
	LOAD_8(out + pos, &packet->hash_algorithm_id);
	pos += 1;

	if (packet->version == PGP_SIGNATURE_V6)
	{
		// 4 octet count for the hashed subpacket data
		uint32_t size = BSWAP_32(packet->hashed_size);

		LOAD_32(out + pos, &size);
		pos += 4;
	}
	else
	{
		// 2 octet count for the hashed subpacket data
		uint16_t size = BSWAP_16(packet->hashed_size);

		LOAD_16(out + pos, &size);
		pos += 2;
	}

	// Hashed subpackets
	pos += pgp_signature_subpacket_write(packet->hashed_data, packet->hashed_size, out + pos);

	if (packet->version == PGP_SIGNATURE_V6)
	{
		// 4 octet count for the unhashed subpacket data
		uint32_t size = BSWAP_32(packet->unhashed_size);

		LOAD_32(out + pos, &size);
		pos += 4;
	}
	else
	{
		// 2 octet count for the unhashed subpacket data
		uint16_t size = BSWAP_16(packet->unhashed_size);

		LOAD_16(out + pos, &size);
		pos += 2;
	}

	// Unhashed subpackets
	pos += pgp_signature_subpacket_write(packet->unhashed_data, packet->unhashed_size, out + pos);

	// 2 octets of the left 16 bits of signed hash value
	LOAD_16(out + pos, &packet->quick_hash);
	pos += 2;

	if (packet->version == PGP_SIGNATURE_V6)
	{
		// 1 octed salt size
		LOAD_8(out + pos, &packet->salt_size);
		pos += 1;

		// Salt
		memcpy(out + pos, packet->salt, packet->salt_size);
		pos += packet->salt_size;
	}

	// Signature data
	pos += pgp_signature_data_write(packet->public_key_algorithm_id, packet->signature, out + pos);

	return pos;
}

uint32_t pgp_signature_packet_write(pgp_signature_packet *packet, void *ptr, uint32_t size)
{
	switch (packet->version)
	{
	case PGP_SIGNATURE_V3:
		return pgp_signature_packet_v3_write(packet, ptr, size);
	case PGP_SIGNATURE_V4:
	case PGP_SIGNATURE_V6:
		return pgp_signature_packet_v4_v6_write(packet, ptr, size);
	default:
		return 0;
	}
}
