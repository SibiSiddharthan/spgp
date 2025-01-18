/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <key.h>
#include <signature.h>

#include <hash.h>
#include <crypto.h>

#include <stdlib.h>
#include <string.h>

static byte_t pgp_signature_type_validate(pgp_signature_type type)
{
	switch (type)
	{
	case PGP_BINARY_SIGNATURE:
	case PGP_TEXT_SIGNATURE:
	case PGP_STANDALONE_SIGNATURE:
	case PGP_GENERIC_CERTIFICATION_SIGNATURE:
	case PGP_PERSONA_CERTIFICATION_SIGNATURE:
	case PGP_CASUAL_CERTIFICATION_SIGNATURE:
	case PGP_POSITIVE_CERTIFICATION_SIGNATURE:
	case PGP_SUBKEY_BINDING_SIGNATURE:
	case PGP_PRIMARY_KEY_BINDING_SIGNATURE:
	case PGP_DIRECT_KEY_SIGNATURE:
	case PGP_KEY_REVOCATION_SIGNATURE:
	case PGP_SUBKEY_REVOCATION_SIGNATURE:
	case PGP_CERTIFICATION_REVOCATION_SIGNATURE:
	case PGP_TIMESTAMP_SIGNATURE:
	case PGP_THIRD_PARTY_CONFIRMATION_SIGNATURE:
		return 1;
	default:
		return 0;
	}
}

static byte_t pgp_signature_subpacket_validate(pgp_signature_subpacket_type type)
{
	switch (type)
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

static size_t pgp_signature_packet_v4_v6_write(pgp_signature_packet *packet, void *ptr, size_t size);

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

static void *pgp_signature_data_read(pgp_signature_packet *packet, void *ptr, uint32_t size)
{
	byte_t *in = ptr;
	uint32_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
	{
		// MPI of (M^d)%n
		pgp_rsa_signature *sig = packet->signature;
		pos = mpi_read(sig->e, in, size);

		if (pos == 0)
		{
			return NULL;
		}

		packet->signature_size = pos;
		return sig;
	}
	case PGP_DSA:
	case PGP_ECDSA:
	{
		// MPI of (r,s)
		pgp_dsa_signature *sig = packet->signature;

		pos += mpi_read(sig->r, in + pos, size - pos);

		if (pos == 0)
		{
			return NULL;
		}

		pos += mpi_read(sig->s, in + pos, size - pos);

		if (pos == 0)
		{
			return NULL;
		}

		packet->signature_size = pos;
		return sig;
	}
	case PGP_ED25519:
	{
		// 64 octets of signature data
		if (size < 64)
		{
			return NULL;
		}

		memcpy(packet->signature, in, 64);
		packet->signature_size = 64;

		return packet->signature;
	}
	case PGP_ED448:
	{
		// 114 octets of signature data
		if (size < 114)
		{
			return NULL;
		}

		memcpy(packet->signature, in, 114);
		packet->signature_size = 114;

		return packet->signature;
	}
	default:
		return NULL;
	}
}

static size_t pgp_signature_data_write(pgp_signature_packet *packet, void *ptr, uint32_t size)
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
		return mpi_write(sig->e, out, size);
	}
	case PGP_DSA:
	case PGP_ECDSA:
	{
		// MPI of (r,s)}
		pgp_dsa_signature *sig = packet->signature;

		pos += mpi_write(sig->r, out + pos, size - pos);
		pos += mpi_write(sig->s, out + pos, size - pos);
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

static void *pgp_signature_subpacket_read(void *subpacket, void *ptr, size_t size)
{
	byte_t *in = ptr;

	pgp_packet_header header = {0};
	size_t pos = 0;

	header = pgp_subpacket_header_read(ptr, size);
	pos = header.header_size;

	if (header.tag == 0)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	switch (header.tag & PGP_SUBPACKET_TAG_MASK)
	{
	case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
	case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
	case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
	{
		struct _pgp_timestamp_subpacket *t = subpacket;
		uint32_t timestamp = 0;

		// Copy the header
		t->header = header;

		// 4 octet timestamp
		LOAD_32(&timestamp, in + pos);
		t->time = BSWAP_32(timestamp);
		pos += 4;
	}
	break;
	case PGP_EXPORTABLE_SUBPACKET:
	case PGP_REVOCABLE_SUBPACKET:
	case PGP_PRIMARY_USER_ID_SUBPACKET:
	{
		struct _pgp_boolean_subpacket *b = subpacket;
		byte_t value = 0;

		// Copy the header
		b->header = header;

		// 1 octet value
		LOAD_8(&value, in + pos);
		b->state = value & 0x1;
		pos += 1;
	}
	break;
	case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
	case PGP_KEY_FLAGS_SUBPACKET:
	case PGP_FEATURES_SUBPACKET:
	{
		struct _pgp_flags_subpacket *flags = subpacket;

		// Copy the header
		flags->header = header;

		// N octets of flags
		memcpy(flags->flags, in + pos, flags->header.body_size);
		pos += flags->header.body_size;
	}
	break;
	case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
	case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
	{
		struct _pgp_preferred_algorithm_subpacket *p = subpacket;

		// Copy the header
		p->header = header;

		// N octets of algorithms
		memcpy(p->preferred_algorithms, in + pos, p->header.body_size);
		pos += p->header.body_size;
	}
	break;
	case PGP_ISSUER_FINGERPRINT_SUBPACKET:
	case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
	{
		struct _pgp_key_fingerprint_subpacket *kf = subpacket;

		// Copy the header
		kf->header = header;

		// 1 octet key version
		LOAD_8(&kf->version, in + pos);
		pos += 1;

		if (kf->version == PGP_KEY_V6)
		{
			// 32 octets of V6 key fingerprint
			memcpy(kf->fingerprint, in + pos, PGP_KEY_V6_FINGERPRINT_SIZE);
			pos += PGP_KEY_V6_FINGERPRINT_SIZE;
		}
		else
		{
			// 20 octets of V4 key fingerprint
			memcpy(kf->fingerprint, in + pos, PGP_KEY_V4_FINGERPRINT_SIZE);
			pos += PGP_KEY_V4_FINGERPRINT_SIZE;
		}
	}
	break;
	case PGP_TRUST_SIGNATURE_SUBPACKET:
	{
		pgp_trust_signature_subpacket *trust = subpacket;

		// Copy the header
		trust->header = header;

		// 1 octet level
		LOAD_8(&trust->trust_level, in + pos);
		pos += 1;

		// 1 octet amount
		LOAD_8(&trust->trust_amount, in + pos);
		pos += 1;
	}
	break;
	case PGP_REGULAR_EXPRESSION_SUBPACKET:
	{
		pgp_regular_expression_subpacket *re = subpacket;

		// Copy the header
		re->header = header;

		// Null terminated UTF-8 string
		memcpy(re->regex, in + pos, re->header.body_size);
		pos += re->header.body_size;
	}
	break;
	case PGP_REVOCATION_KEY_SUBPACKET:
	{
		pgp_revocation_key_subpacket *rk = subpacket;

		// Copy the header
		rk->header = header;

		// 1 octet class
		LOAD_8(&rk->revocation_class, in + pos);
		pos += 1;

		// 1 octet public key algorithm
		LOAD_8(&rk->algorithm_id, in + pos);
		pos += 1;

		// 20 octets v4 key fingerprint
		memcpy(rk->key_fingerprint_v4, in + pos, PGP_KEY_V4_FINGERPRINT_SIZE);
		pos += PGP_KEY_V4_FINGERPRINT_SIZE;
	}
	break;
	case PGP_ISSUER_KEY_ID_SUBPACKET:
	{
		pgp_issuer_key_id_subpacket *ikid = subpacket;

		// Copy the header
		ikid->header = header;

		// 8 octets of key id
		memcpy(ikid->key_id, in + pos, 8);
		pos += 8;
	}
	break;
	case PGP_NOTATION_DATA_SUBPACKET:
	{
		pgp_notation_data_subpacket *nd = subpacket;

		// Copy the header
		nd->header = header;

		uint32_t flags = 0;
		uint16_t name_size = 0;
		uint16_t value_size = 0;

		// 4 octets of flags
		LOAD_32(&flags, in + pos);
		nd->flags = BSWAP_32(flags);
		pos += 4;

		// 2 octets of name length(N)
		LOAD_16(&name_size, in + pos);
		nd->name_size = BSWAP_16(name_size);
		pos += 2;

		// 2 octets of value length(M)
		LOAD_16(&value_size, in + pos);
		nd->value_size = BSWAP_16(value_size);
		pos += 2;

		// (N + M) octets of data
		memcpy(nd->data, in + pos, name_size + value_size);
		pos += name_size + value_size;
	}
	break;
	case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
	{
		pgp_preferred_key_server_subpacket *pks = subpacket;

		// Copy the header
		pks->header = header;

		// String
		memcpy(pks->server, in + pos, pks->header.body_size);
		pos += pks->header.body_size;
	}
	break;
	case PGP_POLICY_URI_SUBPACKET:
	{
		pgp_policy_uri_subpacket *policy = subpacket;

		// Copy the header
		policy->header = header;

		// String
		memcpy(policy->policy, in + pos, policy->header.body_size);
		pos += policy->header.body_size;
	}
	break;
	case PGP_SIGNER_USER_ID_SUBPACKET:
	{
		pgp_signer_user_id_subpacket *uid = subpacket;

		// Copy the header
		uid->header = header;

		// String
		memcpy(uid->id, in + pos, uid->header.body_size);
		pos += uid->header.body_size;
	}
	break;
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
	{
		pgp_reason_for_revocation_subpacket *rr = subpacket;

		// Copy the header
		rr->header = header;

		// 1 octet of revocation code
		LOAD_8(&rr->code, in + pos);
		pos += 1;

		// N octets of reason
		memcpy(rr->reason, in + pos, rr->header.body_size - 1);
		pos += (rr->header.body_size - 1);
	}
	break;
	case PGP_SIGNATURE_TARGET_SUBPACKET:
	{
		pgp_signature_target_subpacket *st = subpacket;

		// Copy the header
		st->header = header;

		// 1 octet public key algorithm
		LOAD_8(&st->public_key_algorithm_id, in + pos);
		pos += 1;

		// 1 octet hash algorithm
		LOAD_8(&st->hash_algorithm_id, in + pos);
		pos += 1;

		// N octets of hash
		memcpy(st->hash, in + pos, st->header.body_size - 2);
		pos += (st->header.body_size - 2);
	}
	break;
	case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
	{
		pgp_embedded_signature_subpacket *es = subpacket;

		// Copy the header
		es->header = header;

		// The buffer should be big enough always.
		return pgp_signature_packet_read(in + pos, size);
	}
	break;
	}

	return NULL;
}

static size_t pgp_signature_subpacket_write(void *subpacket, void *ptr, size_t size)
{
	pgp_subpacket_header *header = subpacket;
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	required_size = header->header_size + header->body_size;

	if (size < required_size)
	{
		return 0;
	}

	pos += pgp_subpacket_header_write(header, out + pos);

	switch (header->tag & PGP_SUBPACKET_TAG_MASK)
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
		memcpy(out + pos, flags->flags, flags->header.body_size);
		pos += flags->header.body_size;
	}
	break;
	case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
	case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
	{
		struct _pgp_preferred_algorithm_subpacket *p = (struct _pgp_preferred_algorithm_subpacket *)header;

		// N octets of algorithms
		memcpy(out + pos, p->preferred_algorithms, p->header.body_size);
		pos += p->header.body_size;
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
		memcpy(out + pos, re->regex, re->header.body_size);
		pos += re->header.body_size;
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
		memcpy(out + pos, pks->server, pks->header.body_size);
		pos += pks->header.body_size;
	}
	break;
	case PGP_POLICY_URI_SUBPACKET:
	{
		pgp_policy_uri_subpacket *policy = (pgp_policy_uri_subpacket *)header;

		// String
		memcpy(out + pos, policy->policy, policy->header.body_size);
		pos += policy->header.body_size;
	}
	break;
	case PGP_SIGNER_USER_ID_SUBPACKET:
	{
		pgp_signer_user_id_subpacket *uid = (pgp_signer_user_id_subpacket *)header;

		// String
		memcpy(out + pos, uid->id, uid->header.body_size);
		pos += uid->header.body_size;
	}
	break;
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
	{
		pgp_reason_for_revocation_subpacket *rr = (pgp_reason_for_revocation_subpacket *)header;

		// 1 octet of revocation code
		LOAD_8(out + pos, &rr->code);
		pos += 1;

		// N octets of reason
		memcpy(out + pos, rr->reason, rr->header.body_size - 1);
		pos += (rr->header.body_size - 1);
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
		memcpy(out + pos, st->hash, st->header.body_size - 2);
		pos += (st->header.body_size - 2);
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

	return pos;
}

static size_t pgp_signature_packet_v3_write(pgp_signature_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number with value 3.
	// A 1-octet length of the following hashed material; it will be 5.
	// A 1-octet Signature Type ID.
	// A 4-octet creation time.
	// An 8-octet Key ID of the signer.
	// A 1-octet public key algorithm.
	// A 1-octet hash algorithm.
	// A 2-octet field holding left 16 bits of the signed hash value.
	// One or more MPIs comprising the signature

	required_size = 1 + 1 + 1 + 4 + 8 + 1 + 1 + 2 + packet->signature_size;
	required_size += packet->header.header_size;

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
	pos += pgp_signature_data_write(packet, out + pos, size - pos);

	return pos;
}

static size_t pgp_signature_packet_v4_v6_write(pgp_signature_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

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

	required_size = 1 + 1 + 1 + 1 + 2 + packet->hashed_size + packet->unhashed_size + packet->signature_size;
	required_size += (packet->version == PGP_SIGNATURE_V6) ? (4 + 4 + 1 + packet->salt_size) : (2 + 2);
	required_size += packet->header.header_size;

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
	for (uint16_t i = 0; i < packet->hashed_subpacket_count; ++i)
	{
		pos += pgp_signature_subpacket_write(packet->hashed_subpackets[i], out + pos, size - pos);
	}

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
	for (uint16_t i = 0; i < packet->unhashed_subpacket_count; ++i)
	{
		pos += pgp_signature_subpacket_write(packet->unhashed_subpackets[i], out + pos, size - pos);
	}

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
	pos += pgp_signature_data_write(packet, out + pos, size - pos);

	return pos;
}

static uint32_t pgp_compute_hash(pgp_signature_packet *packet, void *data, size_t data_size, byte_t hash[64])
{
	hash_ctx *hctx = NULL;

	byte_t hash_buffer[1024] = {0};
	byte_t hash_algorithm = 0;

	uint32_t hashed_size = 0;

	switch (packet->hash_algorithm_id)
	{
	case PGP_MD5:
		hash_algorithm = HASH_MD5;
		break;
	case PGP_SHA1:
		hash_algorithm = HASH_SHA1;
		break;
	case PGP_RIPEMD_160:
		hash_algorithm = HASH_RIPEMD160;
		break;
	case PGP_SHA2_256:
		hash_algorithm = HASH_SHA256;
		break;
	case PGP_SHA2_384:
		hash_algorithm = HASH_SHA384;
		break;
	case PGP_SHA2_512:
		hash_algorithm = HASH_SHA512;
		break;
	case PGP_SHA2_224:
		hash_algorithm = HASH_SHA224;
		break;
	case PGP_SHA3_256:
		hash_algorithm = HASH_SHA3_256;
		break;
	case PGP_SHA3_512:
		hash_algorithm = HASH_SHA3_512;
		break;
	default:
		return 0;
	}

	hctx = hash_init(hash_buffer, 1024, hash_algorithm);

	if (hctx == NULL)
	{
		return 0;
	}

	// Hash the data first
	hash_update(hctx, data, data_size);
	hashed_size += data_size;

	// Hash the trailer
	if (packet->version == PGP_SIGNATURE_V6 || packet->version == PGP_SIGNATURE_V4)
	{
		// 1 octet signature version
		hash_update(hctx, &packet->version, 1);
		hashed_size += 1;

		// 1 octet signature type
		hash_update(hctx, &packet->type, 1);
		hashed_size += 1;

		// 1 octet public key algorithm
		hash_update(hctx, &packet->public_key_algorithm_id, 1);
		hashed_size += 1;

		// 1 octet hash algorithm
		hash_update(hctx, &packet->hash_algorithm_id, 1);
		hashed_size += 1;

		if (packet->version == PGP_SIGNATURE_V6)
		{
			uint32_t hashed_subpacket_size_be = BSWAP_32(packet->hashed_size);

			// 4 octet hashed subpacket size
			hash_update(hctx, &hashed_subpacket_size_be, 4);
			hashed_size += 4;
		}
		else
		{
			uint16_t hashed_subpacket_size_be = BSWAP_16((uint16_t)packet->hashed_size);

			// 2 octet hashed subpacket size
			hash_update(hctx, &hashed_subpacket_size_be, 2);
			hashed_size += 2;
		}

		// Hash the subpackets
		for (uint16_t i = 0; i > packet->hashed_subpackets; ++i)
		{
			byte_t buffer[8];
			pgp_subpacket_header *header = packet->hashed_subpackets[i];

			// Hash the header first
			pgp_subpacket_header_write(header, buffer);
			hash_update(hctx, buffer, header->header_size);
			hashed_size += header->header_size;

			switch (header->tag & PGP_SUBPACKET_TAG_MASK)
			{
			case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
			case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
			case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
			{
				struct _pgp_timestamp_subpacket *subpacket = packet->hashed_subpackets[i];
				uint32_t timestamp_be = BSWAP_32(subpacket->time);

				// 4 octet timestamp
				hash_update(hctx, &timestamp_be, 4);
				hashed_size += 4;
			}
			break;
			case PGP_EXPORTABLE_SUBPACKET:
			case PGP_REVOCABLE_SUBPACKET:
			case PGP_PRIMARY_USER_ID_SUBPACKET:
			{
				struct _pgp_boolean_subpacket *subpacket = packet->hashed_subpackets[i];
				byte_t value = subpacket->state;

				// 1 octet value
				hash_update(hctx, &value, 1);
				hashed_size += 1;
			}
			break;
			case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
			case PGP_KEY_FLAGS_SUBPACKET:
			case PGP_FEATURES_SUBPACKET:
			{
				struct _pgp_flags_subpacket *subpacket = packet->hashed_subpackets[i];

				// N octets of flags
				hash_update(hctx, subpacket->flags, header->body_size);
				hashed_size += header->body_size;
			}
			break;
			case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
			case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
			case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
			case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
			{
				struct _pgp_preferred_algorithm_subpacket *subpacket = packet->hashed_subpackets[i];

				// N octets of algorithms
				hash_update(hctx, subpacket->preferred_algorithms, header->body_size);
				hashed_size += header->body_size;
			}
			break;
			case PGP_ISSUER_FINGERPRINT_SUBPACKET:
			case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
			{
				struct _pgp_key_fingerprint_subpacket *subpacket = packet->hashed_subpackets[i];

				// 1 octet key version
				hash_update(hctx, &subpacket->version, 1);
				hashed_size += 1;

				if (subpacket->version == PGP_KEY_V6)
				{
					// 32 octets of V6 key fingerprint
					hash_update(hctx, subpacket->fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE);
					hashed_size += PGP_KEY_V6_FINGERPRINT_SIZE;
				}
				else
				{
					// 20 octets of V4 key fingerprint
					hash_update(hctx, subpacket->fingerprint, PGP_KEY_V4_FINGERPRINT_SIZE);
					hashed_size += PGP_KEY_V4_FINGERPRINT_SIZE;
				}
			}
			break;
			case PGP_TRUST_SIGNATURE_SUBPACKET:
			{
				pgp_trust_signature_subpacket *subpacket = packet->hashed_subpackets[i];

				// 1 octet level
				hash_update(hctx, &subpacket->trust_level, 1);
				hashed_size += 1;

				// 1 octet amount
				hash_update(hctx, &subpacket->trust_amount, 1);
				hashed_size += 1;
			}
			break;
			case PGP_REGULAR_EXPRESSION_SUBPACKET:
			{
				pgp_regular_expression_subpacket *subpacket = packet->hashed_subpackets[i];

				// Null terminated UTF-8 string
				hash_update(hctx, subpacket->regex, header->body_size);
				hashed_size += header->body_size;
			}
			break;
			case PGP_REVOCATION_KEY_SUBPACKET:
			{
				pgp_revocation_key_subpacket *subpacket = packet->hashed_subpackets[i];

				// 1 octet class
				hash_update(hctx, &subpacket->revocation_class, 1);
				hashed_size += 1;

				// 1 octet public key algorithm
				hash_update(hctx, &subpacket->algorithm_id, 1);
				hashed_size += 1;

				// 20 octets v4 key fingerprint
				hash_update(hctx, subpacket->key_fingerprint_v4, PGP_KEY_V4_FINGERPRINT_SIZE);
				hashed_size += PGP_KEY_V4_FINGERPRINT_SIZE;
			}
			break;
			case PGP_ISSUER_KEY_ID_SUBPACKET:
			{
				pgp_issuer_key_id_subpacket *subpacket = packet->hashed_subpackets[i];

				// 8 octets of key id
				hash_update(hctx, subpacket->key_id, 8);
				hashed_size += 8;
			}
			break;
			case PGP_NOTATION_DATA_SUBPACKET:
			{
				pgp_notation_data_subpacket *subpacket = packet->hashed_subpackets[i];

				uint32_t flags_be = BSWAP_32(subpacket->flags);
				uint16_t name_size_be = BSWAP_16(subpacket->name_size);
				uint16_t value_size_be = BSWAP_16(subpacket->value_size);

				// 4 octets of flags
				hash_update(hctx, &flags_be, 4);
				hashed_size += 4;

				// 2 octets of name length(N)
				hash_update(hctx, &name_size_be, 2);
				hashed_size += 2;

				// 2 octets of value length(M)
				hash_update(hctx, &value_size_be, 2);
				hashed_size += 2;

				// (N + M) octets of data
				hash_update(hctx, subpacket->data, subpacket->name_size + subpacket->value_size);
				hashed_size += subpacket->name_size + subpacket->value_size;
			}
			break;
			case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
			{
				pgp_preferred_key_server_subpacket *subpacket = packet->hashed_subpackets[i];

				// String
				hash_update(hctx, subpacket->server, header->body_size);
				hashed_size += header->body_size;
			}
			break;
			case PGP_POLICY_URI_SUBPACKET:
			{
				pgp_policy_uri_subpacket *subpacket = packet->hashed_subpackets[i];

				// String
				hash_update(hctx, subpacket->policy, header->body_size);
				hashed_size += header->body_size;
			}
			break;
			case PGP_SIGNER_USER_ID_SUBPACKET:
			{
				pgp_signer_user_id_subpacket *subpacket = packet->hashed_subpackets[i];

				// String
				hash_update(hctx, subpacket->id, header->body_size);
				hashed_size += header->body_size;
			}
			break;
			case PGP_REASON_FOR_REVOCATION_SUBPACKET:
			{
				pgp_reason_for_revocation_subpacket *subpacket = packet->hashed_subpackets[i];

				// 1 octet of revocation code
				hash_update(hctx, &subpacket->code, 1);
				hashed_size += 1;

				// N octets of reason
				hash_update(hctx, subpacket->reason, header->body_size - 1);
				hashed_size += header->body_size - 1;
			}
			break;
			case PGP_SIGNATURE_TARGET_SUBPACKET:
			{
				pgp_signature_target_subpacket *subpacket = packet->hashed_subpackets[i];

				// 1 octet public key algorithm
				hash_update(hctx, &subpacket->public_key_algorithm_id, 1);
				hashed_size += 1;

				// 1 octet hash algorithm
				hash_update(hctx, &subpacket->hash_algorithm_id, 1);
				hashed_size += 1;

				// N octets of hash
				hash_update(hctx, subpacket->hash, header->body_size - 2);
				hashed_size += header->body_size - 2;
			}
			break;
			case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
			{
				pgp_embedded_signature_subpacket *subpacket = packet->hashed_subpackets[i];

				// TODO
			}
			break;
			default:
				break;
			}
		}

		// Stop counting the hashed size from here on
		uint32_t hashed_size_be = BSWAP_32(hashed_size);

		// 1 octet signature version (again)
		hash_update(hctx, &packet->version, 1);

		// 1 octet 0xFF
		byte_t byte = 0xFF;
		hash_update(hctx, &byte, 1);

		// 4 octet hashed size
		hash_update(hctx, &hashed_size_be, 4);
	}
	else // packet->version == PGP_SIGNATURE_V3
	{
		// 1 octet signature type
		hash_update(hctx, &packet->type, 1);

		// 4 octet signature creation time
		uint32_t timestamp_be = BSWAP_32(packet->timestamp);
		hash_update(hctx, &timestamp_be, 4);
	}

	hash_final(hctx, hash, 64);

	return hctx->hash_size;
}

pgp_signature_packet *pgp_signature_packet_new(byte_t version, byte_t type, byte_t public_key_algorithm_id, byte_t hash_algorithm_id)
{
	pgp_signature_packet *packet = NULL;

	if (version != PGP_SIGNATURE_V6 && version != PGP_SIGNATURE_V4 && version != PGP_SIGNATURE_V3)
	{
		return NULL;
	}

	if (pgp_signature_type_validate(type) == 0)
	{
		return NULL;
	}

	if (pgp_signature_algorithm_validate(public_key_algorithm_id) == 0)
	{
		return NULL;
	}

	if (pgp_hash_algorithm_validate(hash_algorithm_id) == 0)
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_signature_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_signature_packet));

	packet->version = version;
	packet->type = type;
	packet->public_key_algorithm_id = public_key_algorithm_id;
	packet->hash_algorithm_id = hash_algorithm_id;

	return packet;
}

void pgp_signature_packet_delete(pgp_signature_packet *packet)
{
	// Free the subpackets first
	for (uint16_t i = 0; i < packet->hashed_subpacket_count; ++i)
	{
		free(packet->hashed_subpackets[i]);
	}

	free(packet->hashed_subpackets);

	for (uint16_t i = 0; i < packet->unhashed_subpacket_count; ++i)
	{
		free(packet->unhashed_subpackets[i]);
	}

	free(packet->unhashed_subpackets);

	free(packet->signature);
	free(packet);
}

uint32_t pgp_signature_packet_sign(pgp_signature_packet *packet, pgp_public_key_packet *public_key, void *private_key, void *data,
								   size_t size)
{
	byte_t hash_size = 0;
	byte_t hash[64] = {0};

	hash_size = pgp_compute_hash(packet, data, size, hash);

	if (hash_size == 0)
	{
		return 0;
	}

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
		packet->signature = pgp_rsa_sign(public_key->key_data, private_key, packet->hash_algorithm_id, hash, hash_size);
	case PGP_DSA:
		packet->signature = pgp_dsa_sign(public_key->key_data, private_key, hash, hash_size);
	case PGP_ECDSA:
		packet->signature = pgp_ecdsa_sign(public_key->key_data, private_key, hash, hash_size);
	case PGP_ED25519:
		packet->signature = pgp_ed25519_sign(public_key->key_data, private_key, hash, hash_size);
	case PGP_ED448:
		packet->signature = pgp_ed448_sign(public_key->key_data, private_key, hash, hash_size);
	default:
		return 0;
	}

	return 0;
}

uint32_t pgp_signature_packet_verify(pgp_signature_packet *packet, pgp_public_key_packet *public_key, void *data, size_t size)
{
	byte_t hash_size = 0;
	byte_t hash[64] = {0};

	hash_size = pgp_compute_hash(packet, data, size, hash);

	if (hash_size == 0)
	{
		return 0;
	}

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
		return pgp_rsa_verify(packet->signature, public_key->key_data, packet->hash_algorithm_id, hash, hash_size);
	case PGP_DSA:
		return pgp_dsa_verify(packet->signature, public_key->key_data, hash, hash_size);
	case PGP_ECDSA:
		return pgp_ecdsa_verify(packet->signature, public_key->key_data, hash, hash_size);
	case PGP_ED25519:
		return pgp_ed25519_verify(packet->signature, public_key->key_data, hash, hash_size);
	case PGP_ED448:
		return pgp_ed448_verify(packet->signature, public_key->key_data, hash, hash_size);
	default:
		return 0;
	}

	return 0;
}

pgp_signature_packet *pgp_signature_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_signature_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_PKESK)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_signature_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	// Copy the header
	packet->header = header;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	if (packet->version == PGP_SIGNATURE_V6 || packet->version == PGP_SIGNATURE_V4)
	{
		uint16_t hashed_subpacket_count = 0;
		uint16_t unhashed_subpacket_count = 0;

		uint32_t hashed_subpacket_data_read = 0;
		uint32_t unhashed_subpacket_data_read = 0;

		// 1 octet signature type
		LOAD_8(&packet->type, in + pos);
		pos += 1;

		// 1 octet public key algorithm
		LOAD_8(&packet->public_key_algorithm_id, in + pos);
		pos += 1;

		// 1 octet hash algorithm
		LOAD_8(&packet->hash_algorithm_id, in + pos);
		pos += 1;

		if (packet->version == PGP_SIGNATURE_V6)
		{
			// 4 octet count for the hashed subpacket data
			uint32_t hashed_size = 0;
			LOAD_32(&hashed_size, in + pos);
			packet->hashed_size = BSWAP_32(hashed_size);
			pos += 4;
		}
		else
		{
			// 2 octet count for the hashed subpacket data
			uint32_t hashed_size = 0;
			LOAD_16(&hashed_size, in + pos);
			packet->hashed_size = BSWAP_16(hashed_size);
			pos += 2;
		}

		// Hashed subpackets
		while (hashed_subpacket_data_read < packet->hashed_size)
		{
			pgp_subpacket_header *header = PTR_OFFSET(in, pos);

			header = pgp_signature_subpacket_read(header, in + pos, packet->header.body_size - pos);

			if (header == NULL)
			{
				return NULL;
			}

			packet->hashed_subpackets[hashed_subpacket_count++] = header;
			hashed_subpacket_data_read += header->header_size + header->body_size;
		}

		packet->hashed_subpacket_count = hashed_subpacket_count;
		pos += packet->hashed_size;

		if (packet->version == PGP_SIGNATURE_V6)
		{
			// 4 octet count for the hashed subpacket data
			uint32_t uhashed_size = 0;
			LOAD_32(&uhashed_size, in + pos);
			packet->unhashed_size = BSWAP_32(uhashed_size);
			pos += 4;
		}
		else
		{
			// 2 octet count for the hashed subpacket data
			uint32_t unhashed_size = 0;
			LOAD_16(&unhashed_size, in + pos);
			packet->unhashed_size = BSWAP_16(unhashed_size);
			pos += 2;
		}

		// Unhashed subpackets
		while (unhashed_subpacket_data_read < packet->unhashed_size)
		{
			pgp_subpacket_header *header = PTR_OFFSET(in, pos);

			header = pgp_signature_subpacket_read(header, in + pos, packet->header.body_size - pos);

			if (header == NULL)
			{
				return NULL;
			}

			packet->unhashed_subpackets[unhashed_subpacket_count++] = header;
			unhashed_subpacket_data_read += header->header_size + header->body_size;
		}

		packet->unhashed_subpacket_count = unhashed_subpacket_count;
		pos += packet->unhashed_size;

		// 2 octet field holding left 16 bits of the signed hash value
		LOAD_16(&packet->quick_hash, in + pos);
		pos += 2;

		if (packet->version == PGP_SIGNATURE_V6)
		{
			// 1 octed salt size
			LOAD_8(&packet->salt_size, in + pos);
			pos += 1;

			// Salt
			memcpy(packet->salt, in + pos, packet->salt_size);
			pos += packet->salt_size;
		}

		// Signature data
		packet->signature = pgp_signature_data_read(packet, in + pos, size - pos);

		if (packet->signature == NULL)
		{
			return NULL;
		}
	}
	else if (packet->version == PGP_SIGNATURE_V3)
	{
		// 1 octet hashed length (5)
		LOAD_8(&packet->hashed_size, in + pos);
		pos += 1;

		if (packet->hashed_size != 5)
		{
			return NULL;
		}

		// 1 octet signature type
		LOAD_8(&packet->type, in + pos);
		pos += 1;

		// 4 octet creation time
		uint32_t timestamp = 0;
		LOAD_32(&timestamp, in + pos);
		packet->timestamp = BSWAP_32(timestamp);
		pos += 4;

		// 8 octet key-id
		LOAD_64(&packet->key_id, in + pos);
		pos += 8;

		// 1 octet public key algorithm
		LOAD_8(&packet->public_key_algorithm_id, in + pos);
		pos += 1;

		// 1 octet hash algorithm
		LOAD_8(&packet->hash_algorithm_id, in + pos);
		pos += 1;

		// 2 octet field holding left 16 bits of the signed hash value
		LOAD_16(&packet->quick_hash, in + pos);
		pos += 2;

		// Signature data
		packet->signature = pgp_signature_data_read(packet, in + pos, size - pos);

		if (packet->signature == NULL)
		{
			return NULL;
		}
	}
	else
	{
		// Unknown version.
		return NULL;
	}

	return packet;
}

size_t pgp_signature_packet_write(pgp_signature_packet *packet, void *ptr, size_t size)
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

pgp_one_pass_signature_packet *pgp_one_pass_signature_packet_new(byte_t version, byte_t type, byte_t nested, byte_t public_key_algorithm_id,
																 byte_t hash_algorithm_id, void *salt, byte_t salt_size,
																 void *key_fingerprint, byte_t key_fingerprint_size)
{
	pgp_one_pass_signature_packet *packet = NULL;

	if (version != PGP_ONE_PASS_SIGNATURE_V3 && version != PGP_ONE_PASS_SIGNATURE_V6)
	{
		return NULL;
	}

	if (pgp_signature_type_validate(type) == 0)
	{
		return NULL;
	}

	if (pgp_signature_algorithm_validate(public_key_algorithm_id) == 0)
	{
		return NULL;
	}

	if (pgp_hash_algorithm_validate(hash_algorithm_id) == 0)
	{
		return NULL;
	}

	if (version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		if (key_fingerprint_size != PGP_KEY_V6_FINGERPRINT_SIZE)
		{
			return NULL;
		}

		if (pgp_hash_salt_size(hash_algorithm_id) == 0 || pgp_hash_salt_size(hash_algorithm_id) != salt_size)
		{
			return NULL;
		}
	}
	else
	{
		if (key_fingerprint_size != PGP_KEY_ID_SIZE)
		{
			return NULL;
		}
	}

	packet = malloc(sizeof(pgp_one_pass_signature_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_one_pass_signature_packet));

	packet->version = version;
	packet->type = type;
	packet->nested = nested;
	packet->public_key_algorithm_id = public_key_algorithm_id;
	packet->hash_algorithm_id = hash_algorithm_id;

	if (packet->version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		packet->salt_size = salt_size;
		memcpy(packet->salt, salt, packet->salt_size);

		memcpy(packet->key_fingerprint, key_fingerprint, key_fingerprint_size);

		packet->header = pgp_encode_packet_header(PGP_HEADER, PGP_OPS, 6 + PGP_KEY_V6_FINGERPRINT_SIZE + salt_size);
	}
	else // packet->version == PGP_ONE_PASS_SIGNATURE_V3
	{
		memcpy(packet->key_fingerprint, key_fingerprint, key_fingerprint_size);
		packet->header = pgp_encode_packet_header(PGP_LEGACY_HEADER, PGP_OPS, 5 + PGP_KEY_ID_SIZE);
	}

	return packet;
}

void pgp_one_pass_signature_packet_delete(pgp_one_pass_signature_packet *packet)
{
	free(packet);
}

pgp_one_pass_signature_packet *pgp_one_pass_signature_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_one_pass_signature_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_PKESK)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_one_pass_signature_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	// Copy the header
	packet->header = header;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	// 1 octet signature type
	LOAD_8(&packet->type, in + pos);
	pos += 1;

	// 1 octet hash algorithm
	LOAD_8(&packet->hash_algorithm_id, in + pos);
	pos += 1;

	// 1 octet public-key algorithm
	LOAD_8(&packet->public_key_algorithm_id, in + pos);
	pos += 1;

	if (packet->version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		// 1 octed salt size
		LOAD_8(&packet->salt_size, in + pos);
		pos += 1;

		// Salt
		memcpy(packet->salt, in + pos, packet->salt_size);
		pos += packet->salt_size;

		// A 32-octet key fingerprint.
		memcpy(packet->key_fingerprint, in + pos, 32);
		pos += 32;
	}
	else if (packet->version == PGP_ONE_PASS_SIGNATURE_V3)
	{
		// A 8-octet Key ID of the signer.
		LOAD_64(packet->key_id, in + pos);
		pos += 8;
	}
	else
	{
		// Unknown version.
		return NULL;
	}

	// A 1-octet flag for nested signatures.
	LOAD_8(&packet->nested, in + pos);
	pos += 1;

	return packet;
}

size_t pgp_one_pass_signature_packet_write(pgp_one_pass_signature_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number.
	// A 1-octet Signature Type ID.
	// A 1-octet hash algorithm.
	// A 1-octet public key algorithm.
	// (For V3) A 8-octet Key ID of the signer.
	// (For V6) A 1-octet salt size.
	// (For V6) The salt.
	// (For V6) A 32-octet key fingerprint.
	// A 1-octet flag for nested signatures.

	required_size = packet->header.header_size + 1 + 1 + 1 + 1 + 1;
	required_size += packet->version == PGP_ONE_PASS_SIGNATURE_V6 ? (1 + packet->salt_size + 32) : 8;

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

	// 1 octet hash algorithm
	LOAD_8(out + pos, &packet->hash_algorithm_id);
	pos += 1;

	// 1 octet public-key algorithm
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	if (packet->version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		// 1 octed salt size
		LOAD_8(out + pos, &packet->salt_size);
		pos += 1;

		// Salt
		memcpy(out + pos, packet->salt, packet->salt_size);
		pos += packet->salt_size;

		// A 32-octet key fingerprint.
		memcpy(out + pos, packet->key_fingerprint, 32);
		pos += 32;
	}
	else //(packet->version == PGP_ONE_PASS_SIGNATURE_V3)
	{
		// A 8-octet Key ID of the signer.
		LOAD_64(out + pos, &packet->key_id);
		pos += 8;
	}

	// A 8-octet Key ID of the signer.
	LOAD_64(out + pos, &packet->key_id);
	pos += 8;

	// A 1-octet flag for nested signatures.
	LOAD_8(out + pos, &packet->nested);
	pos += 1;

	return pos;
}
