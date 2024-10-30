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

uint32_t mpi_write_checked(mpi_t *mpi, void *ptr);
uint32_t get_header_size(pgp_packet_header_type type, size_t size);
uint32_t pgp_packet_header_write(pgp_packet_header *header, void *ptr);

static uint32_t pgp_signature_packet_v4_v6_write(pgp_signature_packet *packet, void *ptr, uint32_t size);

uint32_t get_signature_size(pgp_public_key_algorithms algorithm, uint32_t bits)
{
	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
		// MPI of (M^d)%n
		return 2 + CEIL_DIV(bits, 8);
	case PGP_DSA:
	case PGP_ECDSA:
		// MPI of (r,s)
		return (2 + CEIL_DIV(bits, 8)) * 2;
	case PGP_ED25519:
		return 64;
	case PGP_ED448:
		return 114;
	default:
		return 0;
	}
}

uint32_t pgp_signature_data_write(pgp_signature_packet *packet, void *ptr)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
	{
		// MPI of (M^d)%n
		pgp_rsa_signature *sig = packet->signature;
		return mpi_write_checked(sig->e, out);
	}
	case PGP_DSA:
	case PGP_ECDSA:
	{
		// MPI of (r,s)}
		pgp_dsa_signature *sig = packet->signature;

		pos += mpi_write_checked(sig->r, out + pos);
		pos += mpi_write_checked(sig->s, out + pos);
		return pos;
	}
	case PGP_ED25519:
	{
		// 64 octets of signature data
		memcpy(ptr, packet->signature, 64);
		return 64;
	}
	case PGP_ED448:
	{
		// 114 octets of signature data
		memcpy(ptr, packet->signature, 114);
		return 114;
	}
	default:
		return 0;
	}
}

static uint32_t pgp_signature_subpacket_header_write(pgp_signature_subpacket_header *header, void *ptr)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	// Subpacket length

	// 1 octed length
	if (header->size < 192)
	{
		uint8_t size = (uint8_t)header->size;

		LOAD_8(out + pos, &size);
		pos += 1;
	}
	// 2 octet legnth
	else if (header->size < 8384)
	{
		uint16_t size = (uint16_t)header->size - 192;
		uint8_t o1 = (size >> 8) + 192;
		uint8_t o2 = (size & 0xFF);

		LOAD_8(out + pos, &o1);
		pos += 1;

		LOAD_8(out + pos, &o2);
		pos += 1;
	}
	// 5 octet length
	else
	{
		// 1st octet is 255
		uint8_t byte = 255;
		uint32_t size = BSWAP_32((uint32_t)header->size);

		LOAD_8(out + pos, &byte);
		pos += 1;

		LOAD_32(out + pos, &size);
		pos += 4;
	}

	// 1 octet subpacket type
	byte_t tag = header->type | (header->critical << 7);
	LOAD_8(out + pos, &tag);
	pos += 1;

	return pos;
}

static byte_t is_valid_signature_subpacket(pgp_signature_subpacket_header *header)
{
	switch (header->type)
	{
	case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
	case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
	case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
	case PGP_EXPORTABLE_SUBPACKET:
	case PGP_REVOCABLE_SUBPACKET:
	case PGP_PRIMARY_USER_ID_SUBPACKET:
	case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
	case PGP_KEY_FLAGS_SUBPACKET:
	case PGP_FEATURES_SUBPACKET:
	case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
	case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
	case PGP_TRUST_SIGNATURE_SUBPACKET:
	case PGP_REGULAR_EXPRESSION_SUBPACKET:
	case PGP_REVOCATION_KEY_SUBPACKET:
	case PGP_ISSUER_KEY_ID_SUBPACKET:
	case PGP_NOTATION_DATA_SUBPACKET:
	case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
	case PGP_POLICY_URI_SUBPACKET:
	case PGP_SIGNER_USER_ID_SUBPACKET:
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
	case PGP_SIGNATURE_TARGET_SUBPACKET:
	case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
	case PGP_ISSUER_FINGERPRINT_SUBPACKET:
	case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
		return 1;
	default:
		return 0;
	}
}

static uint32_t pgp_signature_subpackets_write(void *data, size_t size, void *ptr)
{
	pgp_signature_subpacket_header *header = NULL;
	signature_subpacket *subpacket = data;
	byte_t *out = ptr;
	uint32_t pos = 0;

	if (size == 0)
	{
		return 0;
	}

	while (subpacket != NULL)
	{
		header = subpacket->data;
		subpacket = subpacket->next;

		pos += pgp_signature_subpacket_header_write(header, out + pos);

		switch (header->type)
		{
		case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
		case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
		case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
		{
			struct _pgp_timestamp_subpacket *t = (struct _pgp_timestamp_subpacket *)header;
			uint32_t timestamp = BSWAP_32(t->time);

			// 4 octet timestamp
			LOAD_32(out + pos, &timestamp);
			pos += 4;
		}
		break;
		case PGP_EXPORTABLE_SUBPACKET:
		case PGP_REVOCABLE_SUBPACKET:
		case PGP_PRIMARY_USER_ID_SUBPACKET:
		{
			struct _pgp_boolean_subpacket *b = (struct _pgp_boolean_subpacket *)header;
			byte_t value = b->state;

			// 1 octet value
			LOAD_8(out + pos, &value);
			pos += 1;
		}
		break;
		case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
		case PGP_KEY_FLAGS_SUBPACKET:
		case PGP_FEATURES_SUBPACKET:
		{
			struct _pgp_flags_subpacket *flags = (struct _pgp_flags_subpacket *)header;

			// N octets of flags
			memcpy(out + pos, flags->flags, flags->header.size);
			pos += flags->header.size;
		}
		break;
		case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
		case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
		case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
		case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
		{
			struct _pgp_preferred_algorithm_subpacket *p = (struct _pgp_preferred_algorithm_subpacket *)header;

			// N octets of algorithms
			memcpy(out + pos, p->preferred_algorithms, p->header.size);
			pos += p->header.size;
		}
		break;
		case PGP_ISSUER_FINGERPRINT_SUBPACKET:
		case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
		{
			struct _pgp_key_fingerprint_subpacket *kf = (struct _pgp_key_fingerprint_subpacket *)header;

			// 1 octet key version
			LOAD_8(out + pos, &kf->version);
			pos += 1;

			if (kf->version == PGP_KEY_V6)
			{
				// 32 octets of V6 key fingerprint
				memcpy(out + pos, kf->fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE);
				pos += PGP_KEY_V6_FINGERPRINT_SIZE;
			}
			else
			{
				// 20 octets of V4 key fingerprint
				memcpy(out + pos, kf->fingerprint, PGP_KEY_V4_FINGERPRINT_SIZE);
				pos += PGP_KEY_V4_FINGERPRINT_SIZE;
			}
		}
		break;
		case PGP_TRUST_SIGNATURE_SUBPACKET:
		{
			pgp_trust_signature_subpacket *trust = (pgp_trust_signature_subpacket *)header;

			// 1 octet level
			LOAD_8(out + pos, &trust->trust_level);
			pos += 1;

			// 1 octet amount
			LOAD_8(out + pos, &trust->trust_amount);
			pos += 1;
		}
		break;
		case PGP_REGULAR_EXPRESSION_SUBPACKET:
		{
			pgp_regular_expression_subpacket *re = (pgp_regular_expression_subpacket *)header;

			// Null terminated UTF-8 string
			memcpy(out + pos, re->regex, re->header.size);
			pos += re->header.size;
		}
		break;
		case PGP_REVOCATION_KEY_SUBPACKET:
		{
			pgp_revocation_key_subpacket *rk = (pgp_revocation_key_subpacket *)header;

			// 1 octet class
			LOAD_8(out + pos, &rk->revocation_class);
			pos += 1;

			// 1 octet public key algorithm
			LOAD_8(out + pos, &rk->algorithm_id);
			pos += 1;

			// 20 octets v4 key fingerprint
			memcpy(out + pos, rk->key_fingerprint_v4, PGP_KEY_V4_FINGERPRINT_SIZE);
			pos += PGP_KEY_V4_FINGERPRINT_SIZE;
		}
		break;
		case PGP_ISSUER_KEY_ID_SUBPACKET:
		{
			pgp_issuer_key_id_subpacket *ikid = (pgp_issuer_key_id_subpacket *)header;

			// 8 octets of key id
			LOAD_64(out + pos, ikid->key_id);
			pos += 8;
		}
		break;
		case PGP_NOTATION_DATA_SUBPACKET:
		{
			pgp_notation_data_subpacket *nd = (pgp_notation_data_subpacket *)header;

			uint32_t flags = BSWAP_32(nd->flags);
			uint16_t name_size = BSWAP_16(nd->name_size);
			uint16_t value_size = BSWAP_16(nd->value_size);

			// 4 octets of flags
			LOAD_32(out + pos, &flags);
			pos += 4;

			// 2 octets of name length(N)
			LOAD_16(out + pos, &name_size);
			pos += 2;

			// 2 octets of value length(M)
			LOAD_16(out + pos, &value_size);
			pos += 2;

			// (N + M) octets of data
			memcpy(out + pos, nd->data, nd->name_size + nd->value_size);
			pos += nd->name_size + nd->value_size;
		}
		break;
		case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
		{
			pgp_preferred_key_server_subpacket *pks = (pgp_preferred_key_server_subpacket *)header;

			// String
			memcpy(out + pos, pks->server, pks->header.size);
			pos += pks->header.size;
		}
		break;
		case PGP_POLICY_URI_SUBPACKET:
		{
			pgp_policy_uri_subpacket *policy = (pgp_policy_uri_subpacket *)header;

			// String
			memcpy(out + pos, policy->policy, policy->header.size);
			pos += policy->header.size;
		}
		break;
		case PGP_SIGNER_USER_ID_SUBPACKET:
		{
			pgp_signer_user_id_subpacket *uid = (pgp_signer_user_id_subpacket *)header;

			// String
			memcpy(out + pos, uid->id, uid->header.size);
			pos += uid->header.size;
		}
		break;
		case PGP_REASON_FOR_REVOCATION_SUBPACKET:
		{
			pgp_reason_for_revocation_subpacket *rr = (pgp_reason_for_revocation_subpacket *)header;

			// 1 octet of revocation code
			LOAD_8(out + pos, &rr->code);
			pos += 1;

			// N octets of reason
			memcpy(out + pos, rr->reason, rr->header.size - 1);
			pos += (rr->header.size - 1);
		}
		break;
		case PGP_SIGNATURE_TARGET_SUBPACKET:
		{
			pgp_signature_target_subpacket *st = (pgp_signature_target_subpacket *)header;

			// 1 octet public key algorithm
			LOAD_8(out + pos, &st->public_key_algorithm_id);
			pos += 1;

			// 1 octet hash algorithm
			LOAD_8(out + pos, &st->hash_algorithm_id);
			pos += 1;

			// N octets of hash
			memcpy(out + pos, st->hash, st->header.size - 2);
			pos += (st->header.size - 2);
		}
		break;
		case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
		{
			pgp_embedded_signature_subpacket *es = (pgp_embedded_signature_subpacket *)header;

			// The buffer should be big enough always.
			pos += pgp_signature_packet_v4_v6_write(es->signature, out + pos, (uint32_t)-1);
		}
		break;
		}
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

	required_size = 1 + 1 + 1 + 4 + 8 + 1 + 1 + 2 + get_signature_size(packet->public_key_algorithm_id, packet->key_bits);
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
	pos += pgp_signature_data_write(packet, out + pos);

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
	// An unhashed subpacket data set (zero or more subpackets).
	// A 2-octet field holding the left 16 bits of the signed hash value.
	// (For V6) A 1-octet salt size.
	// (For V6) The salt.
	// One or more MPIs comprising the signature.

	required_size = 1 + 1 + 1 + 1 + 2 + packet->hashed_size + packet->unhashed_size +
					get_signature_size(packet->public_key_algorithm_id, packet->key_bits);
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
	pos += pgp_signature_subpackets_write(packet->hashed_data, packet->hashed_size, out + pos);

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
	pos += pgp_signature_subpackets_write(packet->unhashed_data, packet->unhashed_size, out + pos);

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
	pos += pgp_signature_data_write(packet, out + pos);

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
