/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
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
	case PGP_ATTESTED_KEY_SIGNATURE:
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

static pgp_error_t pgp_signature_packet_body_read(pgp_signature_packet *packet, buffer_t *buffer);
static size_t pgp_signature_packet_body_write(pgp_signature_packet *packet, void *ptr, size_t size);

static uint32_t get_signature_octets(pgp_public_key_algorithms algorithm, void *signature)
{
	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
	{
		// MPI of (M^d)%n
		pgp_rsa_signature *sign = signature;
		return mpi_octets(sign->e->bits);
	}
	case PGP_DSA:
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		// MPI of (r,s)
		pgp_dsa_signature *sign = signature;
		return mpi_octets(sign->r->bits) + mpi_octets(sign->s->bits);
	}
	case PGP_ED25519:
		return 64;
	case PGP_ED448:
		return 114;
	default:
		return 0;
	}
}

static pgp_error_t pgp_signature_data_read(pgp_signature_packet *packet, void *ptr, uint32_t size)
{
	byte_t *in = ptr;
	uint32_t pos = 0;

	if (size == 0)
	{
		return PGP_EMPTY_SIGNATURE;
	}

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
	{
		// MPI of (M^d)%n
		pgp_rsa_signature *sig = NULL;
		uint16_t mpi_bits = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_RSA_SIGNATURE;
		}

		mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return PGP_MALFORMED_RSA_SIGNATURE;
		}

		sig = malloc(sizeof(pgp_rsa_signature) + mpi_size(mpi_bits));

		if (sig == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(sig, 0, sizeof(pgp_rsa_signature) + mpi_size(mpi_bits));

		sig->e = mpi_init(PTR_OFFSET(sig, sizeof(pgp_rsa_signature)), mpi_size(mpi_bits), mpi_bits);
		pos += mpi_read(sig->e, in, size);

		packet->signature = sig;
		packet->signature_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_DSA:
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		// MPI of (r,s)
		pgp_dsa_signature *sig = NULL;
		pgp_error_t error = 0;
		uint16_t offset = 0;
		uint16_t mpi_r_bits = 0;
		uint16_t mpi_s_bits = 0;
		uint32_t mpi_r_size = 0;
		uint32_t mpi_s_size = 0;

		if (packet->public_key_algorithm_id == PGP_DSA)
		{
			error = PGP_MALFORMED_DSA_SIGNATURE;
		}

		if (packet->public_key_algorithm_id == PGP_ECDSA)
		{
			error = PGP_MALFORMED_ECDSA_SIGNATURE;
		}

		if (packet->public_key_algorithm_id == PGP_EDDSA)
		{
			error = PGP_MALFORMED_EDDSA_SIGNATURE;
		}

		if (size < 2)
		{
			return error;
		}

		mpi_r_bits = ((uint16_t)in[0] << 8) + in[1];
		offset += mpi_octets(mpi_r_bits);

		if (size < (offset + 2))
		{
			return error;
		}

		mpi_s_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_s_bits);

		if (size < offset)
		{
			return error;
		}

		mpi_r_size = mpi_size(mpi_r_bits);
		mpi_s_size = mpi_size(mpi_s_bits);

		sig = malloc(sizeof(pgp_dsa_signature) + mpi_r_size + mpi_s_size);

		if (sig == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(sig, 0, sizeof(pgp_dsa_signature) + mpi_r_size + mpi_s_size);

		sig->r = mpi_init(PTR_OFFSET(sig, sizeof(pgp_dsa_signature)), mpi_r_size, mpi_r_bits);
		sig->s = mpi_init(PTR_OFFSET(sig, sizeof(pgp_dsa_signature) + mpi_r_size), mpi_s_size, mpi_s_bits);

		pos += mpi_read(sig->r, in + pos, size - pos);
		pos += mpi_read(sig->s, in + pos, size - pos);

		packet->signature = sig;
		packet->signature_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_ED25519:
	{
		// 64 octets of signature data
		pgp_ed25519_signature *sig = NULL;

		if (size < 64)
		{
			return PGP_MALFORMED_ED25519_SIGNATURE;
		}

		sig = malloc(sizeof(pgp_ed25519_signature));

		if (sig == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memcpy(sig, in, 64);

		packet->signature = sig;
		packet->signature_octets = 64;

		return PGP_SUCCESS;
	}
	case PGP_ED448:
	{
		// 114 octets of signature data
		pgp_ed448_signature *sig = NULL;

		if (size < 114)
		{
			return PGP_MALFORMED_ED448_SIGNATURE;
		}

		sig = malloc(sizeof(pgp_ed448_signature));

		if (sig == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memcpy(sig, in, 114);

		packet->signature = sig;
		packet->signature_octets = 114;

		return PGP_SUCCESS;
	}
	default:
		packet->signature_octets = size;
		return PGP_SUCCESS;
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
	case PGP_EDDSA:
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

static pgp_error_t pgp_signature_subpacket_read(void **subpacket, buffer_t *buffer)
{
	pgp_error_t error = 0;
	pgp_subpacket_header header = {0};

	error = pgp_subpacket_header_read(&header, buffer->data + buffer->pos, buffer->size - buffer->pos);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (header.tag == 0)
	{
		return PGP_INVALID_SIGNATURE_SUBPACKET_TAG;
	}

	if (buffer->size - buffer->pos < PGP_SUBPACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	buffer->pos += header.header_size;

	switch (header.tag & PGP_SUBPACKET_TAG_MASK)
	{
	case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
	case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
	case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
	{
		struct _pgp_timestamp_subpacket *timestamp_subpacket = NULL;
		pgp_error_t error = 0;

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_SIGNATURE_CREATION_TIME_SUBPACKET)
		{
			error = PGP_MALFORMED_SIGNATURE_CREATION_TIME_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET)
		{
			error = PGP_MALFORMED_SIGNATURE_EXPIRY_TIME_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_KEY_EXPIRATION_TIME_SUBPACKET)
		{
			error = PGP_MALFORMED_KEY_EXPIRATION_TIME_SUBPACKET;
		}

		// Timestamp packets should only be of 4 octets
		if (header.body_size != 4)
		{
			return error;
		}

		timestamp_subpacket = malloc(sizeof(struct _pgp_timestamp_subpacket));

		if (timestamp_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(timestamp_subpacket, 0, sizeof(struct _pgp_timestamp_subpacket));

		// Copy the header
		timestamp_subpacket->header = header;

		// 4 octet timestamp
		CHECK_READ(read32_be(buffer, &timestamp_subpacket->timestamp), error);

		*subpacket = timestamp_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_EXPORTABLE_SUBPACKET:
	case PGP_REVOCABLE_SUBPACKET:
	case PGP_PRIMARY_USER_ID_SUBPACKET:
	{
		struct _pgp_boolean_subpacket *boolean_subpacket = NULL;
		pgp_error_t error = 0;
		byte_t value = 0;

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_EXPORTABLE_SUBPACKET)
		{
			error = PGP_MALFORMED_EXPORTABLE_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_REVOCABLE_SUBPACKET)
		{
			error = PGP_MALFORMED_REVOCABLE_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_PRIMARY_USER_ID_SUBPACKET)
		{
			error = PGP_MALFORMED_PRIMARY_USER_ID_SUBPACKET;
		}

		// Boolean packets should only be of 1 octet
		if (header.body_size != 1)
		{
			return error;
		}

		boolean_subpacket = malloc(sizeof(struct _pgp_boolean_subpacket));

		if (boolean_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(boolean_subpacket, 0, sizeof(struct _pgp_boolean_subpacket));

		// Copy the header
		boolean_subpacket->header = header;

		// 1 octet value
		CHECK_READ(read8(buffer, &value), error);
		boolean_subpacket->state = value & 0x1;

		*subpacket = boolean_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
	case PGP_KEY_FLAGS_SUBPACKET:
	case PGP_FEATURES_SUBPACKET:
	{
		struct _pgp_flags_subpacket *flags_subpacket = NULL;
		pgp_error_t error = 0;

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_KEY_SERVER_PREFERENCES_SUBPACKET)
		{
			error = PGP_MALFORMED_KEY_SERVER_PREFERENCES_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_KEY_FLAGS_SUBPACKET)
		{
			error = PGP_MALFORMED_KEY_FLAGS_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_FEATURES_SUBPACKET)
		{
			error = PGP_MALFORMED_FEATURES_SUBPACKET;
		}

		flags_subpacket = malloc(sizeof(pgp_subpacket_header) + header.body_size);

		if (flags_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(flags_subpacket, 0, sizeof(pgp_subpacket_header) + header.body_size);

		// Copy the header
		flags_subpacket->header = header;

		// N octets of flags
		CHECK_READ(readn(buffer, flags_subpacket->flags, header.body_size), error);

		*subpacket = flags_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
	case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET:
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
	{
		struct _pgp_preferred_algorithm_subpacket *preferred_algorithm_subpacket = NULL;
		pgp_error_t error = 0;

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET)
		{
			error = PGP_MALFORMED_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET)
		{
			error = PGP_MALFORMED_PREFERRED_HASH_ALGORITHMS_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET)
		{
			error = PGP_MALFORMED_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET)
		{
			error = PGP_MALFORMED_PREFERRED_ENCRYPTION_MODES_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET)
		{
			error = PGP_MALFORMED_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET;
		}

		preferred_algorithm_subpacket = malloc(sizeof(pgp_subpacket_header) + header.body_size);

		if (preferred_algorithm_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(preferred_algorithm_subpacket, 0, sizeof(pgp_subpacket_header) + header.body_size);

		// Copy the header
		preferred_algorithm_subpacket->header = header;

		// N octets of algorithms
		CHECK_READ(readn(buffer, preferred_algorithm_subpacket->preferred_algorithms, header.body_size), error);

		*subpacket = preferred_algorithm_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_ISSUER_FINGERPRINT_SUBPACKET:
	case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
	{
		struct _pgp_key_fingerprint_subpacket *key_fingerprint_subpacket = NULL;
		pgp_error_t error = 0;

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_ISSUER_FINGERPRINT_SUBPACKET)
		{
			error = PGP_MALFORMED_ISSUER_FINGERPRINT_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_RECIPIENT_FINGERPRINT_SUBPACKET)
		{
			error = PGP_MALFORMED_RECIPIENT_FINGERPRINT_SUBPACKET;
		}

		// The body size should be only one of 16, 20 or 32 octets plus 1 octet
		if (header.body_size != (PGP_KEY_V3_FINGERPRINT_SIZE + 1) && header.body_size != (PGP_KEY_V4_FINGERPRINT_SIZE + 1) &&
			header.body_size != (PGP_KEY_V6_FINGERPRINT_SIZE + 1))
		{
			return error;
		}

		key_fingerprint_subpacket = malloc(sizeof(struct _pgp_key_fingerprint_subpacket));

		if (key_fingerprint_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key_fingerprint_subpacket, 0, sizeof(struct _pgp_key_fingerprint_subpacket));

		// Copy the header
		key_fingerprint_subpacket->header = header;

		// 1 octet key version
		CHECK_READ(read8(buffer, &key_fingerprint_subpacket->version), error);

		if (key_fingerprint_subpacket->version == PGP_KEY_V6 || key_fingerprint_subpacket->version == PGP_KEY_V5)
		{
			// 32 octets of V6 or V5 key fingerprint
			CHECK_READ(readn(buffer, key_fingerprint_subpacket->fingerprint, 32), error);
		}
		else if (key_fingerprint_subpacket->version == PGP_KEY_V4)
		{
			// 20 octets of V4 key fingerprint
			CHECK_READ(readn(buffer, key_fingerprint_subpacket->fingerprint, 20), error);
		}
		else if (key_fingerprint_subpacket->version == PGP_KEY_V3)
		{
			// 16 octets of V3 key fingerprint
			CHECK_READ(readn(buffer, key_fingerprint_subpacket->fingerprint, 16), error);
		}
		else
		{
			// Unknown key version
			CHECK_READ(readn(buffer, key_fingerprint_subpacket->fingerprint, header.body_size - 1), error);
		}

		*subpacket = key_fingerprint_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_REGULAR_EXPRESSION_SUBPACKET:
	case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
	case PGP_POLICY_URI_SUBPACKET:
	case PGP_SIGNER_USER_ID_SUBPACKET:
	{
		struct _pgp_string_subpacket *string_subpacket = NULL;
		pgp_error_t error = 0;

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_REGULAR_EXPRESSION_SUBPACKET)
		{
			error = PGP_MALFORMED_REGULAR_EXPRESSION_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_PREFERRED_KEY_SERVER_SUBPACKET)
		{
			error = PGP_MALFORMED_PREFERRED_KEY_SERVER_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_POLICY_URI_SUBPACKET)
		{
			error = PGP_MALFORMED_POLICY_URI_SUBPACKET;
		}

		if ((header.tag & PGP_SUBPACKET_TAG_MASK) == PGP_SIGNER_USER_ID_SUBPACKET)
		{
			error = PGP_MALFORMED_SIGNER_USER_ID_SUBPACKET;
		}

		string_subpacket = malloc(sizeof(struct _pgp_string_subpacket) + header.body_size);

		if (string_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(string_subpacket, 0, sizeof(struct _pgp_string_subpacket) + header.body_size);
		string_subpacket->data = PTR_OFFSET(string_subpacket, sizeof(struct _pgp_string_subpacket));

		// Copy the header
		string_subpacket->header = header;

		// Null terminated UTF-8 string
		CHECK_READ(readn(buffer, string_subpacket->data, header.body_size), error);

		*subpacket = string_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_TRUST_SIGNATURE_SUBPACKET:
	{
		pgp_trust_signature_subpacket *trust_subpacket = NULL;

		if (header.body_size != 2)
		{
			return PGP_MALFORMED_TRUST_SIGNATURE_SUBPACKET;
		}

		trust_subpacket = malloc(sizeof(pgp_trust_signature_subpacket));

		if (trust_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(trust_subpacket, 0, sizeof(pgp_trust_signature_subpacket));

		// Copy the header
		trust_subpacket->header = header;

		// 1 octet level
		CHECK_READ(read8(buffer, &trust_subpacket->trust_level), PGP_MALFORMED_TRUST_SIGNATURE_SUBPACKET);

		// 1 octet amount
		CHECK_READ(read8(buffer, &trust_subpacket->trust_amount), PGP_MALFORMED_TRUST_SIGNATURE_SUBPACKET);

		*subpacket = trust_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_REVOCATION_KEY_SUBPACKET:
	{
		pgp_revocation_key_subpacket *revocation_subpacket = NULL;

		revocation_subpacket = malloc(sizeof(pgp_revocation_key_subpacket));

		if (revocation_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(revocation_subpacket, 0, sizeof(pgp_revocation_key_subpacket));

		// Copy the header
		revocation_subpacket->header = header;

		// 1 octet class
		CHECK_READ(read8(buffer, &revocation_subpacket->revocation_class), PGP_MALFORMED_REVOCATION_KEY_SUBPACKET);

		// 1 octet public key algorithm
		CHECK_READ(read8(buffer, &revocation_subpacket->algorithm_id), PGP_MALFORMED_REVOCATION_KEY_SUBPACKET);

		// N octets key fingerprint
		CHECK_READ(readn(buffer, revocation_subpacket->fingerprint, header.body_size - 2), PGP_MALFORMED_REVOCATION_KEY_SUBPACKET);

		*subpacket = revocation_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_ISSUER_KEY_ID_SUBPACKET:
	{
		pgp_issuer_key_id_subpacket *key_id_subpacket = NULL;

		if (header.body_size != PGP_KEY_ID_SIZE)
		{
			return PGP_MALFORMED_ISSUER_KEY_ID_SUBPACKET;
		}

		key_id_subpacket = malloc(sizeof(pgp_issuer_key_id_subpacket));

		if (key_id_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key_id_subpacket, 0, sizeof(pgp_issuer_key_id_subpacket));

		// Copy the header
		key_id_subpacket->header = header;

		// 8 octets of key id
		CHECK_READ(read64(buffer, &key_id_subpacket->key_id), PGP_MALFORMED_ISSUER_KEY_ID_SUBPACKET);

		*subpacket = key_id_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_NOTATION_DATA_SUBPACKET:
	{
		pgp_notation_data_subpacket *notation_subpacket = NULL;

		notation_subpacket = malloc(sizeof(pgp_issuer_key_id_subpacket) + (header.body_size - 8));

		if (notation_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(notation_subpacket, 0, sizeof(pgp_issuer_key_id_subpacket) + (header.body_size - 8));

		// Copy the header
		notation_subpacket->header = header;

		// 4 octets of flags
		CHECK_READ(read32_be(buffer, &notation_subpacket->flags), PGP_MALFORMED_NOTATION_DATA_SUBPACKET);

		// 2 octets of name length(N)
		CHECK_READ(read16_be(buffer, &notation_subpacket->name_size), PGP_MALFORMED_NOTATION_DATA_SUBPACKET);

		// 2 octets of value length(M)
		CHECK_READ(read16_be(buffer, &notation_subpacket->value_size), PGP_MALFORMED_NOTATION_DATA_SUBPACKET);

		// (N + M) octets of data
		CHECK_READ(readn(buffer, notation_subpacket->data, notation_subpacket->name_size + notation_subpacket->value_size),
				   PGP_MALFORMED_NOTATION_DATA_SUBPACKET);

		*subpacket = notation_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
	{
		pgp_reason_for_revocation_subpacket *revocation_reason_subpacket = NULL;

		revocation_reason_subpacket = malloc(sizeof(pgp_reason_for_revocation_subpacket) + header.body_size);

		if (revocation_reason_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(revocation_reason_subpacket, 0, sizeof(pgp_reason_for_revocation_subpacket) + header.body_size);
		revocation_reason_subpacket->reason = PTR_OFFSET(revocation_reason_subpacket, sizeof(pgp_reason_for_revocation_subpacket));

		// Copy the header
		revocation_reason_subpacket->header = header;

		// 1 octet of revocation code
		CHECK_READ(read8(buffer, &revocation_reason_subpacket->code), PGP_MALFORMED_REASON_FOR_REVOCATION_SUBPACKET);

		// N octets of reason
		CHECK_READ(readn(buffer, revocation_reason_subpacket->reason, header.body_size - 1), PGP_MALFORMED_REASON_FOR_REVOCATION_SUBPACKET);

		*subpacket = revocation_reason_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_SIGNATURE_TARGET_SUBPACKET:
	{
		pgp_signature_target_subpacket *target_subpacket = NULL;

		target_subpacket = malloc(sizeof(pgp_subpacket_header) + header.body_size);

		if (target_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(target_subpacket, 0, sizeof(pgp_subpacket_header) + header.body_size);

		// Copy the header
		target_subpacket->header = header;

		// 1 octet public key algorithm
		CHECK_READ(read8(buffer, &target_subpacket->public_key_algorithm_id), PGP_MALFORMED_SIGNATURE_TARGET_SUBPACKET);

		// 1 octet hash algorithm
		CHECK_READ(read8(buffer, &target_subpacket->hash_algorithm_id), PGP_MALFORMED_SIGNATURE_TARGET_SUBPACKET);

		// N octets of hash
		CHECK_READ(readn(buffer, target_subpacket->hash, header.body_size - 2), PGP_MALFORMED_SIGNATURE_TARGET_SUBPACKET);

		*subpacket = target_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
	{
		pgp_error_t error = 0;
		pgp_embedded_signature_subpacket *embedded_subpacket = NULL;

		embedded_subpacket = malloc(sizeof(pgp_embedded_signature_subpacket));

		if (embedded_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(embedded_subpacket, 0, sizeof(pgp_embedded_signature_subpacket));

		// Copy the header
		embedded_subpacket->header = header;
		*subpacket = embedded_subpacket;

		error = pgp_signature_packet_body_read(embedded_subpacket, buffer);

		return error;
	}
	case PGP_ATTESTED_CERTIFICATIONS_SUBPACKET:
	{
		pgp_attested_certifications_subpacket *attestation_subpacket = NULL;

		attestation_subpacket = malloc(sizeof(pgp_attested_certifications_subpacket) + header.body_size);

		if (attestation_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(attestation_subpacket, 0, sizeof(pgp_attested_certifications_subpacket) + header.body_size);
		attestation_subpacket->hash = PTR_OFFSET(attestation_subpacket, sizeof(pgp_attested_certifications_subpacket));

		// N octets of hash
		CHECK_READ(readn(buffer, attestation_subpacket->hash, header.body_size), PGP_MALFORMED_ATTESTED_CERTIFICATIONS_SUBPACKET);

		*subpacket = attestation_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_LITERAL_DATA_META_HASH_SUBPACKET:
	{
		pgp_literal_data_meta_hash_subpacket *meta_subpacket = NULL;

		if (header.body_size != 33)
		{
			return PGP_MALFORMED_LITERAL_DATA_META_HASH_SUBPACKET;
		}

		meta_subpacket = malloc(sizeof(pgp_literal_data_meta_hash_subpacket));

		if (meta_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(meta_subpacket, 0, sizeof(pgp_literal_data_meta_hash_subpacket));

		// Copy the header
		meta_subpacket->header = header;

		// 1 octet
		CHECK_READ(read8(buffer, &meta_subpacket->octet), PGP_MALFORMED_LITERAL_DATA_META_HASH_SUBPACKET);

		// 32 octets of hash
		CHECK_READ(readn(buffer, meta_subpacket->hash, 32), PGP_MALFORMED_LITERAL_DATA_META_HASH_SUBPACKET);

		*subpacket = meta_subpacket;

		return PGP_SUCCESS;
	}
	break;
	default:
	{
		pgp_unknown_subpacket *unknown = malloc(sizeof(pgp_unknown_subpacket) + header.body_size);

		if (unknown == NULL)
		{
			return PGP_NO_MEMORY;
		}

		unknown->header = header;
		unknown->data = PTR_OFFSET(subpacket, sizeof(pgp_unknown_subpacket));
		CHECK_READ(readn(buffer, unknown->data, header.body_size), PGP_INSUFFICIENT_DATA);

		*subpacket = unknown;

		return PGP_SUCCESS;
	}
	}

	return PGP_SUCCESS;
}

static size_t pgp_signature_subpacket_write(void *subpacket, void *ptr, size_t size)
{
	pgp_subpacket_header *header = subpacket;
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_SUBPACKET_OCTETS(*header))
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
		struct _pgp_timestamp_subpacket *timestamp_subpacket = subpacket;

		// 4 octet timestamp
		LOAD_32BE(out + pos, &timestamp_subpacket->timestamp);
		pos += 4;
	}
	break;
	case PGP_EXPORTABLE_SUBPACKET:
	case PGP_REVOCABLE_SUBPACKET:
	case PGP_PRIMARY_USER_ID_SUBPACKET:
	{
		struct _pgp_boolean_subpacket *boolean_subpacket = subpacket;
		byte_t value = boolean_subpacket->state;

		// 1 octet value
		LOAD_8(out + pos, &value);
		pos += 1;
	}
	break;
	case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
	case PGP_KEY_FLAGS_SUBPACKET:
	case PGP_FEATURES_SUBPACKET:
	{
		struct _pgp_flags_subpacket *flags_subpacket = subpacket;

		// N octets of flags
		memcpy(out + pos, flags_subpacket->flags, flags_subpacket->header.body_size);
		pos += flags_subpacket->header.body_size;
	}
	break;
	case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
	case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
	case PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET:
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
	{
		struct _pgp_preferred_algorithm_subpacket *preferred_algorithm_subpacket = subpacket;

		// N octets of algorithms
		memcpy(out + pos, preferred_algorithm_subpacket->preferred_algorithms, preferred_algorithm_subpacket->header.body_size);
		pos += preferred_algorithm_subpacket->header.body_size;
	}
	break;
	case PGP_ISSUER_FINGERPRINT_SUBPACKET:
	case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
	{
		struct _pgp_key_fingerprint_subpacket *key_fingerprint_subpacket = subpacket;

		// 1 octet key version
		LOAD_8(out + pos, &key_fingerprint_subpacket->version);
		pos += 1;

		if (key_fingerprint_subpacket->version == PGP_KEY_V6)
		{
			// 32 octets of V6 key fingerprint
			memcpy(out + pos, key_fingerprint_subpacket->fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE);
			pos += PGP_KEY_V6_FINGERPRINT_SIZE;
		}
		else if (key_fingerprint_subpacket->version == PGP_KEY_V4)
		{
			// 20 octets of V4 key fingerprint
			memcpy(out + pos, key_fingerprint_subpacket->fingerprint, PGP_KEY_V4_FINGERPRINT_SIZE);
			pos += PGP_KEY_V4_FINGERPRINT_SIZE;
		}
		else // V3
		{
			// 16 octets of V3 key fingerprint
			memcpy(out + pos, key_fingerprint_subpacket->fingerprint, PGP_KEY_V3_FINGERPRINT_SIZE);
			pos += PGP_KEY_V3_FINGERPRINT_SIZE;
		}
	}
	break;
	case PGP_REGULAR_EXPRESSION_SUBPACKET:
	case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
	case PGP_POLICY_URI_SUBPACKET:
	case PGP_SIGNER_USER_ID_SUBPACKET:
	{
		struct _pgp_string_subpacket *string_subpacket = subpacket;

		// String
		memcpy(out + pos, string_subpacket->data, string_subpacket->header.body_size);
		pos += string_subpacket->header.body_size;
	}
	break;
	case PGP_TRUST_SIGNATURE_SUBPACKET:
	{
		pgp_trust_signature_subpacket *trust_subpacket = subpacket;

		// 1 octet level
		LOAD_8(out + pos, &trust_subpacket->trust_level);
		pos += 1;

		// 1 octet amount
		LOAD_8(out + pos, &trust_subpacket->trust_amount);
		pos += 1;
	}
	break;
	case PGP_REVOCATION_KEY_SUBPACKET:
	{
		pgp_revocation_key_subpacket *rk_subpacket = subpacket;

		// 1 octet class
		LOAD_8(out + pos, &rk_subpacket->revocation_class);
		pos += 1;

		// 1 octet public key algorithm
		LOAD_8(out + pos, &rk_subpacket->algorithm_id);
		pos += 1;

		// N octets key fingerprint
		memcpy(out + pos, rk_subpacket->fingerprint, rk_subpacket->header.body_size - 2);
		pos += rk_subpacket->header.body_size - 2;
	}
	break;
	case PGP_ISSUER_KEY_ID_SUBPACKET:
	{
		pgp_issuer_key_id_subpacket *key_id_subpacket = subpacket;

		// 8 octets of key id
		LOAD_64(out + pos, key_id_subpacket->key_id);
		pos += 8;
	}
	break;
	case PGP_NOTATION_DATA_SUBPACKET:
	{
		pgp_notation_data_subpacket *notation_subpacket = subpacket;

		// 4 octets of flags
		LOAD_32BE(out + pos, &notation_subpacket->flags);
		pos += 4;

		// 2 octets of name length(N)
		LOAD_16BE(out + pos, &notation_subpacket->name_size);
		pos += 2;

		// 2 octets of value length(M)
		LOAD_16BE(out + pos, &notation_subpacket->value_size);
		pos += 2;

		// (N + M) octets of data
		memcpy(out + pos, notation_subpacket->data, notation_subpacket->name_size + notation_subpacket->value_size);
		pos += notation_subpacket->name_size + notation_subpacket->value_size;
	}
	break;
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
	{
		pgp_reason_for_revocation_subpacket *revocation_reason_subpacket = subpacket;

		// 1 octet of revocation code
		LOAD_8(out + pos, &revocation_reason_subpacket->code);
		pos += 1;

		// N octets of reason
		memcpy(out + pos, revocation_reason_subpacket->reason, revocation_reason_subpacket->header.body_size - 1);
		pos += (revocation_reason_subpacket->header.body_size - 1);
	}
	break;
	case PGP_SIGNATURE_TARGET_SUBPACKET:
	{
		pgp_signature_target_subpacket *target_subpacket = subpacket;

		// 1 octet public key algorithm
		LOAD_8(out + pos, &target_subpacket->public_key_algorithm_id);
		pos += 1;

		// 1 octet hash algorithm
		LOAD_8(out + pos, &target_subpacket->hash_algorithm_id);
		pos += 1;

		// N octets of hash
		memcpy(out + pos, target_subpacket->hash, target_subpacket->header.body_size - 2);
		pos += (target_subpacket->header.body_size - 2);
	}
	break;
	case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
	{
		pgp_embedded_signature_subpacket *embedded_subpacket = subpacket;

		pos += pgp_signature_packet_body_write(embedded_subpacket, out + pos, PGP_SUBPACKET_OCTETS(*header));
	}
	break;
	case PGP_ATTESTED_CERTIFICATIONS_SUBPACKET:
	{
		pgp_attested_certifications_subpacket *attestation_subpacket = subpacket;

		// N octets of hash
		memcpy(out + pos, attestation_subpacket->hash, attestation_subpacket->header.body_size);
		pos += attestation_subpacket->header.body_size;
	}
	break;
	case PGP_LITERAL_DATA_META_HASH_SUBPACKET:
	{
		pgp_literal_data_meta_hash_subpacket *meta_subpacket = subpacket;

		// 1 octet
		LOAD_8(out + pos, &meta_subpacket->octet);
		pos += 1;

		// 1 octet hash algorithm
		memcpy(out + pos, meta_subpacket->hash, 32);
		pos += 32;
	}
	break;
	}

	return pos;
}

static void pgp_signature_subpacket_delete(void *subpacket)
{
	pgp_subpacket_header *header = subpacket;

	switch (header->tag & PGP_SUBPACKET_TAG_MASK)
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
	case PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET:
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
	case PGP_ISSUER_FINGERPRINT_SUBPACKET:
	case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
	case PGP_REGULAR_EXPRESSION_SUBPACKET:
	case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
	case PGP_POLICY_URI_SUBPACKET:
	case PGP_SIGNER_USER_ID_SUBPACKET:
	case PGP_TRUST_SIGNATURE_SUBPACKET:
	case PGP_REVOCATION_KEY_SUBPACKET:
	case PGP_ISSUER_KEY_ID_SUBPACKET:
	case PGP_NOTATION_DATA_SUBPACKET:
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
	case PGP_SIGNATURE_TARGET_SUBPACKET:
	case PGP_ATTESTED_CERTIFICATIONS_SUBPACKET:
	case PGP_LITERAL_DATA_META_HASH_SUBPACKET:
		free(subpacket);
		break;
	case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
		pgp_signature_packet_delete(subpacket);
		break;
	case PGP_KEY_BLOCK_SUBPACKET:
		pgp_key_packet_delete(subpacket);
		break;
	default:
		free(subpacket);
		break;
	}
}

static void pgp_signature_packet_encode_header(pgp_signature_packet *packet)
{
	uint32_t body_size = 0;

	if (packet->version >= PGP_SIGNATURE_V4)
	{
		// A 1-octet version number.
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

		body_size = 1 + 1 + 1 + 1 + 2 + packet->hashed_octets + packet->unhashed_octets + packet->signature_octets;
		body_size += (packet->version == PGP_SIGNATURE_V6) ? (4 + 4 + 1 + packet->salt_size) : (2 + 2);
		packet->header = pgp_encode_packet_header(PGP_LEGACY_HEADER, PGP_SIG, body_size);
	}
	else
	{
		// A 1-octet version number with value 3.
		// A 1-octet length of the following hashed material; it will be 5.
		// A 1-octet Signature Type ID.
		// A 4-octet creation time.
		// An 8-octet Key ID of the signer.
		// A 1-octet public key algorithm.
		// A 1-octet hash algorithm.
		// A 2-octet field holding left 16 bits of the signed hash value.
		// One or more MPIs comprising the signature

		body_size = 1 + 1 + 1 + 4 + 8 + 1 + 1 + 2 + packet->signature_octets;
		packet->header = pgp_encode_packet_header(PGP_LEGACY_HEADER, PGP_SIG, body_size);
	}
}

static size_t pgp_signature_packet_v3_write(pgp_signature_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 1 octet hashed length
	LOAD_8(out + pos, &packet->hashed_octets);
	pos += 1;

	// 1 octet signature type
	LOAD_8(out + pos, &packet->type);
	pos += 1;

	// 4 octet timestamp
	LOAD_32BE(out + pos, &packet->timestamp);
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

static size_t pgp_signature_packet_body_write(pgp_signature_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

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
		LOAD_32BE(out + pos, &packet->hashed_octets);
		pos += 4;
	}
	else
	{
		// 2 octet count for the hashed subpacket data
		LOAD_16BE(out + pos, &packet->hashed_octets);
		pos += 2;
	}

	// Hashed subpackets
	if (packet->hashed_subpackets != NULL)
	{
		for (uint16_t i = 0; i < packet->hashed_subpackets->count; ++i)
		{
			pos += pgp_signature_subpacket_write(packet->hashed_subpackets->packets[i], out + pos, size - pos);
		}
	}

	if (packet->version == PGP_SIGNATURE_V6)
	{
		// 4 octet count for the unhashed subpacket data
		LOAD_32BE(out + pos, &packet->unhashed_octets);
		pos += 4;
	}
	else
	{
		// 2 octet count for the unhashed subpacket data
		LOAD_16BE(out + pos, &size);
		pos += 2;
	}

	// Unhashed subpackets
	if (packet->unhashed_subpackets != NULL)
	{
		for (uint16_t i = 0; i < packet->unhashed_subpackets->count; ++i)
		{
			pos += pgp_signature_subpacket_write(packet->unhashed_subpackets->packets[i], out + pos, size - pos);
		}
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

static size_t pgp_signature_packet_v4_v5_v6_write(pgp_signature_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Body
	pos += pgp_signature_packet_body_write(packet, PTR_OFFSET(out, pos), size - pos);

	return pos;
}

static void pgp_compute_literal_hash(hash_ctx *hctx, pgp_literal_packet *literal)
{
	// Hash the data
	hash_update(hctx, literal->data, literal->data_size);

	// Hash the partials
	if (literal->partials)
	{
		pgp_partial_packet *packet = NULL;

		for (uint16_t i = 0; i < literal->partials->count; ++i)
		{
			packet = literal->partials->packets[i];
			hash_update(hctx, packet->data, packet->header.body_size);
		}
	}
}

static void pgp_compute_uid_hash(hash_ctx *hctx, byte_t version, pgp_user_id_packet *uid)
{
	byte_t octet = 0xB4;
	uint32_t size_be = BSWAP_32(uid->header.body_size);

	if (version != PGP_SIGNATURE_V3)
	{
		// 1 octet 0xB4
		hash_update(hctx, &octet, 1);

		// 4 octet data length
		hash_update(hctx, &size_be, 4);
	}

	// Data
	hash_update(hctx, uid->user_data, uid->header.body_size);
}

static void pgp_compute_uat_hash(hash_ctx *hctx, byte_t version, pgp_user_attribute_packet *uat)
{
	byte_t octet = 0xD1;
	uint32_t size_be = BSWAP_32(uat->header.body_size);

	if (version != PGP_SIGNATURE_V3)
	{
		// 1 octet 0xD1
		hash_update(hctx, &octet, 1);

		// 4 octet data length
		hash_update(hctx, &size_be, 4);
	}

	// Data
	if (uat->subpackets != NULL)
	{
		pgp_subpacket_header *header = NULL;
		byte_t buffer[8] = {0};
		uint32_t size = 0;

		for (uint16_t i = 0; i < uat->subpackets->count; ++i)
		{
			header = uat->subpackets->packets[i];

			// Hash the header
			size = pgp_subpacket_header_write(header, buffer);
			hash_update(hctx, buffer, size);

			switch (header->tag & PGP_SUBPACKET_TAG_MASK)
			{
			case PGP_USER_ATTRIBUTE_IMAGE:
			{
				pgp_user_attribute_image_subpacket *subpacket = uat->subpackets->packets[i];
				byte_t image_header[16] = {0};

				// 16 octets of image header
				image_header[0] = subpacket->image_header_size & 0xFF;
				image_header[1] = (subpacket->image_header_size >> 8) & 0xFF;
				image_header[2] = subpacket->image_header_version;
				image_header[3] = subpacket->image_encoding;

				hash_update(hctx, image_header, 16);
				hash_update(hctx, subpacket->image_data, header->body_size - 16);
			}
			case PGP_USER_ATTRIBUTE_UID:
			{
				pgp_user_attribute_uid_subpacket *subpacket = uat->subpackets->packets[i];
				hash_update(hctx, subpacket->user_data, header->body_size);
			}
			break;
			}
		}
	}
}

static void pgp_compute_certification_hash(hash_ctx *hctx, byte_t version, pgp_key_packet *key, void *user)
{
	pgp_packet_header *header = user;

	pgp_key_hash(hctx, key);

	if (pgp_packet_get_type(header->tag) == PGP_UAT)
	{
		pgp_compute_uat_hash(hctx, version, user);
	}

	pgp_compute_uid_hash(hctx, version, user);
}

static uint32_t pgp_compute_hash(pgp_signature_packet *packet, pgp_key_packet *key, byte_t hash[64], void *data)
{
	hash_ctx *hctx = NULL;

	byte_t hash_buffer[1024] = {0};
	byte_t hash_algorithm = 0;

	uint64_t hashed_size = 0;
	uint32_t max_subpacket_size = 0;

	void *subpacket_buffer = NULL;

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

	// Hash the salt first
	if (packet->version == PGP_SIGNATURE_V6)
	{
		hash_update(hctx, packet->salt, packet->salt_size);
	}

	// Hash the data first
	switch (packet->type)
	{
	case PGP_BINARY_SIGNATURE:
		pgp_compute_literal_hash(hctx, data);
		break;
	case PGP_TEXT_SIGNATURE:
		pgp_compute_literal_hash(hctx, data);
		break;
	case PGP_STANDALONE_SIGNATURE:
		// Nothing to hash here.
		break;

	case PGP_GENERIC_CERTIFICATION_SIGNATURE:
	case PGP_PERSONA_CERTIFICATION_SIGNATURE:
	case PGP_CASUAL_CERTIFICATION_SIGNATURE:
	case PGP_POSITIVE_CERTIFICATION_SIGNATURE:
		pgp_compute_certification_hash(hctx, packet->version, key, data);
		break;

	case PGP_SUBKEY_BINDING_SIGNATURE:
	case PGP_SUBKEY_REVOCATION_SIGNATURE:
		pgp_key_hash(hctx, key);  // Primary key
		pgp_key_hash(hctx, data); // Subkey
		break;

	case PGP_PRIMARY_KEY_BINDING_SIGNATURE:
		pgp_key_hash(hctx, data); // Primary key
		pgp_key_hash(hctx, key);  // Subkey

	case PGP_KEY_REVOCATION_SIGNATURE:
		pgp_key_hash(hctx, key); // Primary key
		break;

	case PGP_TIMESTAMP_SIGNATURE:
		// hash_update(hctx, data, data_size); TODO
		break;
	}

	// Hash the trailer
	if (packet->version == PGP_SIGNATURE_V6 || packet->version == PGP_SIGNATURE_V5 || packet->version == PGP_SIGNATURE_V4)
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
			uint32_t hashed_subpacket_size_be = BSWAP_32(packet->hashed_octets);

			// 4 octet hashed subpacket size
			hash_update(hctx, &hashed_subpacket_size_be, 4);
			hashed_size += 4;
		}
		else
		{
			uint16_t hashed_subpacket_size_be = BSWAP_16((uint16_t)packet->hashed_octets);

			// 2 octet hashed subpacket size
			hash_update(hctx, &hashed_subpacket_size_be, 2);
			hashed_size += 2;
		}

		// Hash the subpackets
		for (uint16_t i = 0; i < packet->hashed_subpackets->count; ++i)
		{
			pgp_subpacket_header *header = packet->hashed_subpackets->packets[i];

			max_subpacket_size = MAX(max_subpacket_size, header->body_size + header->header_size);
		}

		max_subpacket_size = ROUND_UP(max_subpacket_size, 16);
		subpacket_buffer = malloc(max_subpacket_size);

		if (subpacket_buffer == NULL)
		{
			return 0;
		}

		for (uint16_t i = 0; i < packet->hashed_subpackets->count; ++i)
		{
			uint32_t subpacket_size = 0;

			// Write the subpackets to the buffer then hash them.
			memset(subpacket_buffer, 0, max_subpacket_size);

			subpacket_size = pgp_signature_subpacket_write(packet->hashed_subpackets->packets[i], subpacket_buffer, max_subpacket_size);

			hash_update(hctx, subpacket_buffer, subpacket_size);
			hashed_size += subpacket_size;
		}

		free(subpacket_buffer);

		if (packet->version == PGP_SIGNATURE_V5 && (packet->type == PGP_BINARY_SIGNATURE || packet->type == PGP_TEXT_SIGNATURE))
		{
			pgp_literal_packet *literal = data;

			// 1 octet content format
			hash_update(hctx, &literal->format, 1);

			// 1 octet file name length
			hash_update(hctx, &literal->filename_size, 1);

			// N octets of file name
			if (literal->filename_size > 0)
			{
				hash_update(hctx, &literal->filename, literal->filename_size);
			}

			// 4 octets of date
			uint32_t date_be = BSWAP_32(literal->date);
			hash_update(hctx, &date_be, 4);
		}

		// Stop counting the hashed size from here on

		// 1 octet signature version (again)
		hash_update(hctx, &packet->version, 1);

		// 1 octet 0xFF
		byte_t byte = 0xFF;
		hash_update(hctx, &byte, 1);

		if (packet->version == PGP_SIGNATURE_V5)
		{
			// 8 octet hashed size
			uint64_t hashed_size_be = BSWAP_64((uint64_t)hashed_size);
			hash_update(hctx, &hashed_size_be, 8);
		}
		else
		{
			// 4 octet hashed size
			uint32_t hashed_size_be = BSWAP_32((uint32_t)hashed_size);
			hash_update(hctx, &hashed_size_be, 4);
		}
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

pgp_error_t pgp_signature_packet_new(pgp_signature_packet **packet, byte_t version, byte_t type)
{
	pgp_signature_packet *sign = NULL;

	if (version < PGP_SIGNATURE_V3 || version > PGP_SIGNATURE_V6)
	{
		return PGP_INVALID_SIGNATURE_PACKET_VERSION;
	}

	if (pgp_signature_type_validate(type) == 0)
	{
		return PGP_INVALID_SIGNATURE_TYPE;
	}

	sign = malloc(sizeof(pgp_signature_packet));

	if (sign == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(sign, 0, sizeof(pgp_signature_packet));

	sign->version = version;
	sign->type = type;

	*packet = sign;

	return PGP_SUCCESS;
}

void pgp_signature_packet_delete(pgp_signature_packet *packet)
{
	if (packet == NULL)
	{
		return;
	}

	// Free the subpackets first
	pgp_stream_delete(packet->hashed_subpackets, pgp_signature_subpacket_delete);
	pgp_stream_delete(packet->unhashed_subpackets, pgp_signature_subpacket_delete);
	free(packet->signature);
	free(packet);
}

static pgp_error_t pgp_signature_packet_sign_setup(pgp_signature_packet *packet, pgp_key_packet *key, uint32_t timestamp)
{
	pgp_timestamp_subpacket *timestamp_subpacket = NULL;
	pgp_key_fingerprint_subpacket *fingerprint_subpacket = NULL;
	pgp_issuer_key_id_subpacket *key_id_subpacket = NULL;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = 0;

	// Calculate issuer key fingerprint
	fingerprint_size = pgp_key_fingerprint(key, fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);
	fingerprint_subpacket =
		pgp_key_fingerprint_subpacket_new(PGP_ISSUER_FINGERPRINT_SUBPACKET, key->version, fingerprint, fingerprint_size);

	timestamp_subpacket = pgp_timestamp_subpacket_new(PGP_SIGNATURE_CREATION_TIME_SUBPACKET, timestamp);

	if (timestamp_subpacket == NULL || fingerprint_subpacket == NULL)
	{
		pgp_timestamp_subpacket_delete(timestamp_subpacket);
		pgp_key_fingerprint_subpacket_delete(fingerprint_subpacket);

		return PGP_NO_MEMORY;
	}

	pgp_signature_packet_hashed_subpacket_add(packet, timestamp_subpacket);
	pgp_signature_packet_hashed_subpacket_add(packet, fingerprint_subpacket);

	// Only for V4 signatures append the key id as an unhashed subpacket
	if (packet->version == PGP_SIGNATURE_V4)
	{
		key_id_subpacket = pgp_issuer_key_id_subpacket_new(PTR_OFFSET(fingerprint, fingerprint_size - PGP_KEY_ID_SIZE));

		if (key_id_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		pgp_signature_packet_unhashed_subpacket_add(packet, key_id_subpacket);
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_signature_packet_sign(pgp_signature_packet *packet, pgp_key_packet *key, pgp_hash_algorithms hash_algorithm,
									  uint32_t timestamp, void *data)
{
	pgp_error_t error = 0;
	byte_t hash_size = 0;
	byte_t hash[64] = {0};

	if (pgp_hash_algorithm_validate(hash_algorithm) == 0)
	{
		return PGP_INVALID_HASH_ALGORITHM;
	}

	// Incompatible signature and key versions
	if (packet->version != key->version)
	{
		return PGP_INCOMPATIBLE_SIGNATURE_AND_KEY_VERSION;
	}

	if ((key->capabilities & PGP_KEY_FLAG_SIGN) == 0)
	{
		return PGP_UNUSABLE_KEY_FOR_SIGNING;
	}

	if (key->encrypted != NULL)
	{
		return PGP_KEY_NOT_DECRYPTED;
	}

	// Set the algorithms
	packet->public_key_algorithm_id = key->public_key_algorithm_id;
	packet->hash_algorithm_id = hash_algorithm;

	if (packet->hashed_subpackets == NULL)
	{
		error = pgp_signature_packet_sign_setup(packet, key, timestamp);

		if (error != PGP_SUCCESS)
		{
			pgp_signature_packet_delete(packet);
			return error;
		}
	}

	hash_size = pgp_compute_hash(packet, key, hash, data);

	if (hash_size == 0)
	{
		return 0;
	}

	// Store the left 2 octets
	packet->quick_hash[0] = hash[0];
	packet->quick_hash[1] = hash[1];

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
		packet->signature = pgp_rsa_sign(key->key, packet->hash_algorithm_id, hash, hash_size);
		break;
	case PGP_DSA:
		packet->signature = pgp_dsa_sign(key->key, hash, hash_size);
		break;
	case PGP_ECDSA:
		packet->signature = pgp_ecdsa_sign(key->key, hash, hash_size);
		break;
	case PGP_EDDSA:
		packet->signature = pgp_eddsa_sign(key->key, hash, hash_size);
		break;
	case PGP_ED25519:
		packet->signature = pgp_ed25519_sign(key->key, hash, hash_size);
		break;
	case PGP_ED448:
		packet->signature = pgp_ed448_sign(key->key, hash, hash_size);
		break;
	default:
		return 0;
	}

	packet->signature_octets = get_signature_octets(packet->public_key_algorithm_id, packet->signature);
	pgp_signature_packet_encode_header(packet);

	return PGP_SUCCESS;
}

pgp_error_t pgp_signature_packet_verify(pgp_signature_packet *packet, pgp_key_packet *key, void *data)
{
	byte_t hash_size = 0;
	byte_t hash[64] = {0};

	if ((key->capabilities & PGP_KEY_FLAG_SIGN) == 0)
	{
		return PGP_UNUSABLE_KEY_FOR_SIGNING;
	}

	hash_size = pgp_compute_hash(packet, key, hash, data);

	if (hash_size == 0)
	{
		return 0;
	}

	// Check the left 2 octets first
	if (hash[0] != packet->quick_hash[0] || hash[1] != packet->quick_hash[1])
	{
		return 0;
	}

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
		return pgp_rsa_verify(packet->signature, key->key, packet->hash_algorithm_id, hash, hash_size);
	case PGP_DSA:
		return pgp_dsa_verify(packet->signature, key->key, hash, hash_size);
	case PGP_ECDSA:
		return pgp_ecdsa_verify(packet->signature, key->key, hash, hash_size);
	case PGP_EDDSA:
		return pgp_eddsa_verify(packet->signature, key->key, hash, hash_size);
	case PGP_ED25519:
		return pgp_ed25519_verify(packet->signature, key->key, hash, hash_size);
	case PGP_ED448:
		return pgp_ed448_verify(packet->signature, key->key, hash, hash_size);
	default:
		return 0;
	}

	return 0;
}

pgp_error_t pgp_generate_document_signature(pgp_signature_packet **packet, pgp_key_packet *key, byte_t version, byte_t type, byte_t flags,
											pgp_hash_algorithms hash_algorithm, uint32_t timestamp, pgp_literal_packet *literal)
{
	pgp_error_t error = 0;
	pgp_signature_packet *sign = NULL;

	byte_t format_copy = 0;
	byte_t filename_size_copy = 0;
	uint32_t date_copy = 0;

	if (version < PGP_SIGNATURE_V3 || version > PGP_SIGNATURE_V6)
	{
		return PGP_INVALID_SIGNATURE_PACKET_VERSION;
	}

	if (type != PGP_BINARY_SIGNATURE && type != PGP_TEXT_SIGNATURE)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (type == PGP_TEXT_SIGNATURE)
	{
		if (literal->format != PGP_LITERAL_DATA_MIME && literal->format != PGP_LITERAL_DATA_TEXT &&
			literal->format != PGP_LITERAL_DATA_UTF8)
		{
			return PGP_INVALID_LITERAL_PACKET_FORMAT_FOR_TEXT_SIGNATURE;
		}
	}

	sign = malloc(sizeof(pgp_signature_packet));

	if (sign == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(sign, 0, sizeof(pgp_signature_packet));

	sign->version = version;
	sign->type = type;

	error = pgp_signature_packet_sign_setup(sign, key, timestamp);

	if (error != PGP_SUCCESS)
	{
		pgp_signature_packet_delete(sign);
		return error;
	}

	// If these flags are set modify the literal packet
	// Make a copy of the literal fields
	format_copy = literal->format;
	filename_size_copy = literal->filename_size;
	date_copy = literal->date;

	if (flags == PGP_SIGNATURE_FLAG_DETACHED)
	{
		// 6 octets of zero
		literal->format = 0;
		literal->filename_size = 0;
		literal->date = 0;
	}

	if (flags == PGP_SIGNATURE_FLAG_CLEARTEXT)
	{
		// 1 octet of 't'
		// 5 octets of zero
		literal->format = PGP_LITERAL_DATA_TEXT;
		literal->filename_size = 0;
		literal->date = 0;
	}

	error = pgp_signature_packet_sign(sign, key, hash_algorithm, timestamp, literal);

	// Restore the fields
	literal->format = format_copy;
	literal->filename_size = filename_size_copy;
	literal->date = date_copy;

	if (error != PGP_SUCCESS)
	{
		pgp_signature_packet_delete(sign);
		return error;
	}

	*packet = sign;

	return PGP_SUCCESS;
}

pgp_error_t pgp_verify_document_signature(pgp_signature_packet *sign, pgp_key_packet *key, pgp_literal_packet *literal)
{
	if (sign->type != PGP_BINARY_SIGNATURE && sign->type != PGP_TEXT_SIGNATURE)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (sign->type == PGP_TEXT_SIGNATURE)
	{
		if (literal->format != PGP_LITERAL_DATA_MIME && literal->format != PGP_LITERAL_DATA_TEXT &&
			literal->format != PGP_LITERAL_DATA_UTF8)
		{
			return PGP_INVALID_LITERAL_PACKET_FORMAT_FOR_TEXT_SIGNATURE;
		}
	}

	return pgp_signature_packet_verify(sign, key, literal);
}

pgp_error_t pgp_generate_key_binding_signature(pgp_signature_packet **packet, pgp_key_packet *key, pgp_key_packet *subkey, byte_t version,
											   byte_t type, pgp_hash_algorithms hash_algorithm, uint32_t timestamp, uint32_t expiry,
											   uint32_t flags)
{
	pgp_error_t error = 0;
	pgp_signature_packet *sign = NULL;

	if (version < PGP_SIGNATURE_V3 || version > PGP_SIGNATURE_V6)
	{
		return PGP_INVALID_SIGNATURE_PACKET_VERSION;
	}

	if (type != PGP_SUBKEY_BINDING_SIGNATURE && type != PGP_PRIMARY_KEY_BINDING_SIGNATURE)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	sign = malloc(sizeof(pgp_signature_packet));

	if (sign == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(sign, 0, sizeof(pgp_signature_packet));

	sign->version = version;
	sign->type = type;

	error = pgp_signature_packet_sign_setup(sign, key, timestamp);

	if (error != PGP_SUCCESS)
	{
		pgp_signature_packet_delete(sign);
		return error;
	}

	if (type == PGP_SUBKEY_BINDING_SIGNATURE)
	{
		pgp_key_flags_subpacket *flags_subpacket = NULL;
		pgp_key_expiration_time_subpacket *expiry_subpacket = NULL;

		// Add key flags subpacket
		flags_subpacket = pgp_flags_subpacket_new(PGP_KEY_FLAGS_SUBPACKET, flags);

		if (flags_subpacket == NULL)
		{
			pgp_signature_packet_delete(sign);
			return PGP_NO_MEMORY;
		}

		pgp_signature_packet_hashed_subpacket_add(sign, flags_subpacket);

		// Add key expiration subpacket
		if (expiry > 0)
		{
			expiry_subpacket = pgp_timestamp_subpacket_new(PGP_KEY_EXPIRATION_TIME_SUBPACKET, expiry);

			if (expiry_subpacket == NULL)
			{
				free(flags_subpacket);
				pgp_signature_packet_delete(sign);

				return PGP_NO_MEMORY;
			}

			pgp_signature_packet_hashed_subpacket_add(sign, expiry_subpacket);
		}

		error = pgp_signature_packet_sign(sign, key, hash_algorithm, timestamp, subkey);
	}
	else
	{
		error = pgp_signature_packet_sign(sign, subkey, hash_algorithm, timestamp, key);
	}

	if (error != PGP_SUCCESS)
	{
		pgp_signature_packet_delete(sign);
		return error;
	}

	*packet = sign;

	return PGP_SUCCESS;
}

pgp_error_t pgp_verify_key_binding_signature(pgp_signature_packet *sign, pgp_key_packet *key, pgp_key_packet *subkey)
{
	if (sign->type == PGP_SUBKEY_BINDING_SIGNATURE)
	{
		return pgp_signature_packet_verify(sign, key, subkey);
	}

	if (sign->type == PGP_PRIMARY_KEY_BINDING_SIGNATURE)
	{
		return pgp_signature_packet_verify(sign, subkey, key);
	}

	return PGP_INCORRECT_FUNCTION;
}

static pgp_error_t pgp_signature_packet_body_read(pgp_signature_packet *packet, buffer_t *buffer)
{
	pgp_error_t error = 0;
	void *result = NULL;

	size_t old_size = 0;

	// 1 octet version
	CHECK_READ(read8(buffer, &packet->version), PGP_MALFORMED_SIGNATURE_PACKET);

	if (packet->version == PGP_SIGNATURE_V6 || packet->version == PGP_SIGNATURE_V5 || packet->version == PGP_SIGNATURE_V4)
	{
		// 1 octet signature type
		CHECK_READ(read8(buffer, &packet->type), PGP_MALFORMED_SIGNATURE_PACKET);

		// 1 octet public key algorithm
		CHECK_READ(read8(buffer, &packet->public_key_algorithm_id), PGP_MALFORMED_SIGNATURE_PACKET);

		// 1 octet hash algorithm
		CHECK_READ(read8(buffer, &packet->hash_algorithm_id), PGP_MALFORMED_SIGNATURE_PACKET);

		if (packet->version == PGP_SIGNATURE_V6)
		{
			// 4 octet count for the hashed subpacket data
			CHECK_READ(read32_be(buffer, &packet->hashed_octets), PGP_MALFORMED_SIGNATURE_PACKET);
		}
		else
		{
			// 2 octet count for the hashed subpacket data
			CHECK_READ(read16_be(buffer, &packet->hashed_octets), PGP_MALFORMED_SIGNATURE_PACKET);
		}

		// Hashed subpackets
		old_size = buffer->size;
		buffer->size = buffer->pos + packet->hashed_octets;

		while (buffer->pos < buffer->size)
		{
			void *subpacket = NULL;

			error = pgp_signature_subpacket_read(&subpacket, buffer);

			if (error != PGP_SUCCESS)
			{
				// Just a free should be enough here.
				// The embedded signature subpacket is freed in pgp_signature_subpacket_read.
				if (subpacket != NULL)
				{
					free(subpacket);
				}

				if (error == PGP_INSUFFICIENT_DATA)
				{
					return PGP_MALFORMED_SIGNATURE_HASHED_SUBPACKET_SIZE;
				}

				return error;
			}

			result = pgp_stream_push_packet(packet->hashed_subpackets, subpacket);

			if (result == NULL)
			{
				return PGP_NO_MEMORY;
			}

			packet->hashed_subpackets = result;
		}

		buffer->size = old_size;

		if (packet->version == PGP_SIGNATURE_V6)
		{
			// 4 octet count for the hashed subpacket data
			CHECK_READ(read32_be(buffer, &packet->unhashed_octets), PGP_MALFORMED_SIGNATURE_PACKET);
		}
		else
		{
			// 2 octet count for the hashed subpacket data
			CHECK_READ(read16_be(buffer, &packet->unhashed_octets), PGP_MALFORMED_SIGNATURE_PACKET);
		}

		// Unhashed subpackets
		old_size = buffer->size;
		buffer->size = buffer->pos + packet->unhashed_octets;

		while (buffer->pos < buffer->size)
		{
			void *subpacket = NULL;

			error = pgp_signature_subpacket_read(&subpacket, buffer);

			if (error != PGP_SUCCESS)
			{
				// Just a free should be enough here.
				// The embedded signature subpacket is freed in pgp_signature_subpacket_read.
				if (subpacket != NULL)
				{
					free(subpacket);
				}

				if (error == PGP_INSUFFICIENT_DATA)
				{
					return PGP_MALFORMED_SIGNATURE_UNHASHED_SUBPACKET_SIZE;
				}

				return error;
			}

			result = pgp_stream_push_packet(packet->unhashed_subpackets, subpacket);

			if (result == NULL)
			{
				return PGP_NO_MEMORY;
			}

			packet->unhashed_subpackets = result;
		}

		buffer->size = old_size;

		// 2 octet field holding left 16 bits of the signed hash value
		CHECK_READ(read16(buffer, &packet->quick_hash), PGP_MALFORMED_SIGNATURE_PACKET);

		if (packet->version == PGP_SIGNATURE_V6)
		{
			// 1 octed salt size
			CHECK_READ(read16(buffer, &packet->salt_size), PGP_MALFORMED_SIGNATURE_PACKET);

			// Salt
			CHECK_READ(readn(buffer, packet->salt, packet->salt_size), PGP_MALFORMED_SIGNATURE_PACKET_SALT_SIZE);
		}

		// Signature data
		error = pgp_signature_data_read(packet, buffer->data + buffer->pos, buffer->size - buffer->pos);

		if (error != PGP_SUCCESS)
		{
			return error;
		}

		buffer->pos += packet->signature_octets;
	}
	else if (packet->version == PGP_SIGNATURE_V3)
	{
		// 1 octet hashed length (5)
		CHECK_READ(read8(buffer, &packet->hashed_octets), PGP_MALFORMED_SIGNATURE_PACKET);

		if (packet->hashed_octets != 5)
		{
			return PGP_MALFORMED_SIGNATURE_PACKET;
		}

		// 1 octet signature type
		CHECK_READ(read8(buffer, &packet->type), PGP_MALFORMED_SIGNATURE_PACKET);

		// 4 octet creation time
		CHECK_READ(read32_be(buffer, &packet->timestamp), PGP_MALFORMED_SIGNATURE_PACKET);

		// 8 octet key-id
		CHECK_READ(readn(buffer, &packet->key_id, PGP_KEY_ID_SIZE), PGP_MALFORMED_SIGNATURE_PACKET);

		// 1 octet public key algorithm
		CHECK_READ(read8(buffer, &packet->public_key_algorithm_id), PGP_MALFORMED_SIGNATURE_PACKET);

		// 1 octet hash algorithm
		CHECK_READ(read8(buffer, &packet->hash_algorithm_id), PGP_MALFORMED_SIGNATURE_PACKET);

		// 2 octet field holding left 16 bits of the signed hash value
		CHECK_READ(read16(buffer, &packet->quick_hash), PGP_MALFORMED_SIGNATURE_PACKET);

		// Signature data
		error = pgp_signature_data_read(packet, buffer->data + buffer->pos, buffer->size - buffer->pos);

		if (error != PGP_SUCCESS)
		{
			return error;
		}

		buffer->pos += packet->signature_octets;
	}
	else
	{
		// Unknown version.
		return PGP_INVALID_SIGNATURE_PACKET_VERSION;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_signature_packet_read_with_header(pgp_signature_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_signature_packet *signature = NULL;

	signature = malloc(sizeof(pgp_signature_packet));

	if (signature == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(signature, 0, sizeof(pgp_signature_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	signature->header = *header;

	// Read the body
	error = pgp_signature_packet_body_read(signature, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_signature_packet_delete(signature);
		return error;
	}

	*packet = signature;

	return error;
}

pgp_error_t pgp_signature_packet_read(pgp_signature_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_get_type(header.tag) != PGP_LIT)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_signature_packet_read_with_header(packet, &header, data);
}

size_t pgp_signature_packet_write(pgp_signature_packet *packet, void *ptr, size_t size)
{
	switch (packet->version)
	{
	case PGP_SIGNATURE_V3:
		return pgp_signature_packet_v3_write(packet, ptr, size);
	case PGP_SIGNATURE_V4:
	case PGP_SIGNATURE_V6:
		return pgp_signature_packet_v4_v5_v6_write(packet, ptr, size);
	default:
		return 0;
	}
}

pgp_signature_packet *pgp_signature_packet_hashed_subpacket_add(pgp_signature_packet *packet, void *subpacket)
{
	void *result = NULL;
	pgp_subpacket_header *header = subpacket;

	result = pgp_stream_push_packet(packet->hashed_subpackets, subpacket);

	if (result == NULL)
	{
		return NULL;
	}

	packet->hashed_subpackets = result;
	packet->hashed_octets += header->header_size + header->body_size;

	return packet;
}

pgp_signature_packet *pgp_signature_packet_unhashed_subpacket_add(pgp_signature_packet *packet, void *subpacket)
{
	void *result = NULL;
	pgp_subpacket_header *header = subpacket;

	result = pgp_stream_push_packet(packet->unhashed_subpackets, subpacket);

	if (result == NULL)
	{
		return NULL;
	}

	packet->unhashed_subpackets = result;
	packet->unhashed_octets += header->header_size + header->body_size;

	return packet;
}

pgp_timestamp_subpacket *pgp_timestamp_subpacket_new(byte_t tag, uint32_t timestamp)
{
	pgp_timestamp_subpacket *subpacket = NULL;

	// Check tag
	if (tag != PGP_SIGNATURE_CREATION_TIME_SUBPACKET && tag != PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET &&
		tag != PGP_KEY_EXPIRATION_TIME_SUBPACKET)
	{
		return NULL;
	}

	subpacket = malloc(sizeof(pgp_timestamp_subpacket));

	if (subpacket == NULL)
	{
		return NULL;
	}

	memset(subpacket, 0, sizeof(pgp_timestamp_subpacket));

	subpacket->header = pgp_encode_subpacket_header(tag, 1, 4);
	subpacket->timestamp = timestamp;

	return subpacket;
}

void pgp_timestamp_subpacket_delete(pgp_timestamp_subpacket *subpacket)
{
	free(subpacket);
}

pgp_key_fingerprint_subpacket *pgp_key_fingerprint_subpacket_new(byte_t tag, byte_t version, byte_t *fingerprint, byte_t size)
{
	pgp_key_fingerprint_subpacket *subpacket = NULL;

	// Check tag
	if (tag != PGP_ISSUER_FINGERPRINT_SUBPACKET && tag != PGP_RECIPIENT_FINGERPRINT_SUBPACKET)
	{
		return NULL;
	}

	// Check key version
	if (version != PGP_KEY_V4 && version != PGP_KEY_V5 && version != PGP_KEY_V6)
	{
		return NULL;
	}

	subpacket = malloc(sizeof(pgp_key_fingerprint_subpacket));

	if (subpacket == NULL)
	{
		return NULL;
	}

	memset(subpacket, 0, sizeof(pgp_key_fingerprint_subpacket));

	subpacket->version = version;
	memcpy(subpacket->fingerprint, fingerprint, size);

	subpacket->header = pgp_encode_subpacket_header(tag, 1, size + 1);

	return subpacket;
}

void pgp_key_fingerprint_subpacket_delete(pgp_key_fingerprint_subpacket *subpacket)
{
	free(subpacket);
}

pgp_issuer_key_id_subpacket *pgp_issuer_key_id_subpacket_new(byte_t key_id[PGP_KEY_ID_SIZE])
{
	pgp_issuer_key_id_subpacket *subpacket = malloc(sizeof(pgp_issuer_key_id_subpacket));

	if (subpacket == NULL)
	{
		return NULL;
	}

	memset(subpacket, 0, sizeof(pgp_issuer_key_id_subpacket));
	memcpy(subpacket->key_id, key_id, PGP_KEY_ID_SIZE);

	subpacket->header = pgp_encode_subpacket_header(PGP_ISSUER_KEY_ID_SUBPACKET, 0, PGP_KEY_ID_SIZE);

	return subpacket;
}

void pgp_issuer_key_id_subpacket_delete(pgp_issuer_key_id_subpacket *subpacket)
{
	free(subpacket);
}

pgp_flags_subpacket *pgp_flags_subpacket_new(byte_t tag, uint32_t flags)
{
	pgp_flags_subpacket *subpacket = NULL;

	if (tag != PGP_KEY_FLAGS_SUBPACKET && tag != PGP_FEATURES_SUBPACKET && tag != PGP_KEY_SERVER_PREFERENCES_SUBPACKET)
	{
		return NULL;
	}

	// Allocate for 4 bytes of flags
	subpacket = malloc(sizeof(pgp_subpacket_header) + 4);

	if (subpacket == NULL)
	{
		return NULL;
	}

	memset(subpacket, 0, sizeof(pgp_subpacket_header) + 4);

	if (tag == PGP_KEY_FLAGS_SUBPACKET)
	{
		subpacket->flags[0] = flags & PGP_KEY_FLAG_FIRST_OCTET_MASK;

		if ((flags >> 8) == 0)
		{
			subpacket->header = pgp_encode_subpacket_header(PGP_KEY_FLAGS_SUBPACKET, 1, 1);
		}
		else
		{
			subpacket->flags[1] = (flags >> 8) & PGP_KEY_FLAG_SECOND_OCTET_MASK;
			subpacket->header = pgp_encode_subpacket_header(PGP_KEY_FLAGS_SUBPACKET, 1, 2);
		}
	}

	if (tag == PGP_FEATURES_SUBPACKET)
	{
		subpacket->flags[0] = flags & PGP_FEATURE_FLAG_MASK;
		subpacket->header = pgp_encode_subpacket_header(PGP_FEATURES_SUBPACKET, 0, 1);
	}

	if (tag == PGP_KEY_SERVER_PREFERENCES_SUBPACKET)
	{
		subpacket->flags[0] = flags & PGP_KEY_SERVER_FLAGS_MASK;
		subpacket->header = pgp_encode_subpacket_header(PGP_KEY_SERVER_PREFERENCES_SUBPACKET, 0, 1);
	}

	return subpacket;
}

void pgp_key_flags_subpacket_delete(pgp_key_flags_subpacket *subpacket)
{
	free(subpacket);
}

pgp_error_t pgp_one_pass_signature_packet_new(pgp_one_pass_signature_packet **packet, byte_t version, byte_t type, byte_t nested,
											  byte_t public_key_algorithm_id, byte_t hash_algorithm_id, void *salt, byte_t salt_size,
											  void *key_fingerprint, byte_t key_fingerprint_size)
{
	pgp_one_pass_signature_packet *ops = NULL;

	if (version != PGP_ONE_PASS_SIGNATURE_V3 && version != PGP_ONE_PASS_SIGNATURE_V6)
	{
		return PGP_INVALID_ONE_PASS_SIGNATURE_PACKET_VERSION;
	}

	if (pgp_signature_type_validate(type) == 0)
	{
		return PGP_INVALID_SIGNATURE_TYPE;
	}

	if (pgp_signature_algorithm_validate(public_key_algorithm_id) == 0)
	{
		return PGP_INVALID_SIGNATURE_ALGORITHM;
	}

	if (pgp_hash_algorithm_validate(hash_algorithm_id) == 0)
	{
		return PGP_INVALID_HASH_ALGORITHM;
	}

	if (version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		if (key_fingerprint_size != PGP_KEY_V6_FINGERPRINT_SIZE)
		{
			return PGP_INVALID_PARAMETER;
		}

		if (pgp_hash_salt_size(hash_algorithm_id) == 0 || pgp_hash_salt_size(hash_algorithm_id) != salt_size)
		{
			return PGP_INVALID_HASH_SALT_SIZE;
		}
	}
	else
	{
		if (key_fingerprint_size != PGP_KEY_ID_SIZE)
		{
			return PGP_INVALID_PARAMETER;
		}
	}

	ops = malloc(sizeof(pgp_one_pass_signature_packet));

	if (ops == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(ops, 0, sizeof(pgp_one_pass_signature_packet));

	// A 1-octet version number.
	// A 1-octet Signature Type ID.
	// A 1-octet hash algorithm.
	// A 1-octet public key algorithm.
	// (For V3) A 8-octet Key ID of the signer.
	// (For V6) A 1-octet salt size.
	// (For V6) The salt.
	// (For V6) A 32-octet key fingerprint.
	// A 1-octet flag for nested signatures.

	ops->version = version;
	ops->type = type;
	ops->nested = nested;
	ops->public_key_algorithm_id = public_key_algorithm_id;
	ops->hash_algorithm_id = hash_algorithm_id;

	if (ops->version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		ops->salt_size = salt_size;
		memcpy(ops->salt, salt, ops->salt_size);

		memcpy(ops->key_fingerprint, key_fingerprint, key_fingerprint_size);

		ops->header = pgp_encode_packet_header(PGP_HEADER, PGP_OPS, 6 + PGP_KEY_V6_FINGERPRINT_SIZE + salt_size);
	}
	else // packet->version == PGP_ONE_PASS_SIGNATURE_V3
	{
		memcpy(ops->key_fingerprint, key_fingerprint, key_fingerprint_size);
		ops->header = pgp_encode_packet_header(PGP_LEGACY_HEADER, PGP_OPS, 5 + PGP_KEY_ID_SIZE);
	}

	*packet = ops;

	return PGP_SUCCESS;
}

void pgp_one_pass_signature_packet_delete(pgp_one_pass_signature_packet *packet)
{
	free(packet);
}

static pgp_error_t pgp_one_pass_signature_packet_read_body(pgp_one_pass_signature_packet *packet, buffer_t *buffer)
{
	// 1 octet version
	CHECK_READ(read8(buffer, &packet->version), PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET);

	// 1 octet signature type
	CHECK_READ(read8(buffer, &packet->type), PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET);

	// 1 octet hash algorithm
	CHECK_READ(read8(buffer, &packet->hash_algorithm_id), PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET);

	// 1 octet public-key algorithm
	CHECK_READ(read8(buffer, &packet->public_key_algorithm_id), PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET);

	if (packet->version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		// 1 octed salt size
		CHECK_READ(read8(buffer, &packet->salt_size), PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET);

		// Salt
		CHECK_READ(readn(buffer, packet->salt, packet->salt_size), PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET);

		// A 32-octet key fingerprint.
		CHECK_READ(readn(buffer, packet->key_fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE), PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET);
	}
	else if (packet->version == PGP_ONE_PASS_SIGNATURE_V3)
	{
		// A 8-octet Key ID of the signer.
		CHECK_READ(readn(buffer, packet->key_id, PGP_KEY_ID_SIZE), PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET);
	}
	else
	{
		// Unknown version.
		return PGP_INVALID_ONE_PASS_SIGNATURE_PACKET_VERSION;
	}

	// A 1-octet flag for nested signatures.
	CHECK_READ(read8(buffer, &packet->nested), PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET);

	return PGP_SUCCESS;
}

pgp_error_t pgp_one_pass_signature_packet_read_with_header(pgp_one_pass_signature_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_one_pass_signature_packet *ops = NULL;

	ops = malloc(sizeof(pgp_one_pass_signature_packet));

	if (ops == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(ops, 0, sizeof(pgp_one_pass_signature_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	ops->header = *header;

	// Read the body
	error = pgp_one_pass_signature_packet_read_body(ops, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_one_pass_signature_packet_delete(ops);
		return error;
	}

	*packet = ops;

	return error;
}

pgp_error_t pgp_one_pass_signature_packet_read(pgp_one_pass_signature_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_get_type(header.tag) != PGP_OPS)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_one_pass_signature_packet_read_with_header(packet, &header, data);
}

size_t pgp_one_pass_signature_packet_write(pgp_one_pass_signature_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
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

pgp_rsa_signature *pgp_rsa_signature_new(uint16_t bits)
{
	pgp_rsa_signature *sign = NULL;

	sign = malloc(sizeof(pgp_rsa_signature) + mpi_size(bits));

	if (sign == NULL)
	{
		return NULL;
	}

	memset(sign, 0, sizeof(pgp_rsa_signature) + mpi_size(bits));

	// Initialize the MPI
	sign->e = mpi_init(PTR_OFFSET(sign, sizeof(pgp_rsa_signature)), mpi_size(bits), bits);

	return sign;
}

void pgp_rsa_signature_delete(pgp_rsa_signature *sign)
{
	free(sign);
}

pgp_dsa_signature *pgp_dsa_signature_new(uint16_t bits)
{
	pgp_dsa_signature *sign = NULL;

	sign = malloc(sizeof(pgp_dsa_signature) + (2 * mpi_size(bits)));

	if (sign == NULL)
	{
		return NULL;
	}

	memset(sign, 0, sizeof(pgp_dsa_signature) + mpi_size(bits));

	// Initialize the MPIs
	sign->r = mpi_init(PTR_OFFSET(sign, sizeof(pgp_dsa_signature)), mpi_size(bits), bits);
	sign->s = mpi_init(PTR_OFFSET(sign, sizeof(pgp_dsa_signature) + mpi_size(bits)), mpi_size(bits), bits);

	return sign;
}

void pgp_dsa_signature_delete(pgp_dsa_signature *sign)
{
	free(sign);
}
