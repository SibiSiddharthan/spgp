/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
#include <algorithms.h>
#include <crypto.h>
#include <packet.h>
#include <session.h>

#include <string.h>
#include <stdlib.h>

static pgp_error_t pgp_session_key_read(pgp_pkesk_packet *packet, void *data, uint32_t size)
{
	byte_t *in = data;
	size_t pos = 0;

	if (size == 0)
	{
		return PGP_INSUFFICIENT_DATA;
	}

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	{
		// MPI of (m^e) mod n
		pgp_rsa_kex *sk = NULL;
		uint16_t mpi_bits = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_RSA_SESSION_KEY;
		}

		mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return PGP_MALFORMED_RSA_SESSION_KEY;
		}

		sk = malloc(sizeof(pgp_rsa_kex) + mpi_size(mpi_bits));

		if (sk == NULL)
		{
			return PGP_NO_MEMORY;
		}

		sk->c = mpi_init(PTR_OFFSET(sk, sizeof(pgp_rsa_kex)), mpi_size(mpi_bits), mpi_bits);
		pos += mpi_read(sk->c, in, size);

		packet->encrypted_session_key = sk;
		packet->encrypted_session_key_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		// MPI of (g^k) mod p
		// MPI of m * (y^k) mod p
		pgp_elgamal_kex *sk = NULL;
		uint16_t offset = 0;
		uint16_t mpi_r_bits = 0;
		uint16_t mpi_s_bits = 0;
		uint32_t mpi_r_size = 0;
		uint32_t mpi_s_size = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_ELGAMAL_SESSION_KEY;
		}

		mpi_r_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_r_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_ELGAMAL_SESSION_KEY;
		}

		mpi_s_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_s_bits);

		if (size < offset)
		{
			return PGP_MALFORMED_ELGAMAL_SESSION_KEY;
		}

		mpi_r_size = mpi_size(mpi_r_bits);
		mpi_s_size = mpi_size(mpi_s_bits);

		sk = malloc(sizeof(pgp_elgamal_kex) + mpi_r_size + mpi_s_size);

		if (sk == NULL)
		{
			return PGP_NO_MEMORY;
		}

		sk->r = mpi_init(PTR_OFFSET(sk, sizeof(pgp_elgamal_kex)), mpi_r_size, mpi_r_bits);
		sk->s = mpi_init(PTR_OFFSET(sk, sizeof(pgp_elgamal_kex) + mpi_r_size), mpi_s_size, mpi_s_bits);

		pos += mpi_read(sk->r, in + pos, size - pos);
		pos += mpi_read(sk->s, in + pos, size - pos);

		packet->encrypted_session_key = sk;
		packet->encrypted_session_key_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_kex *sk = NULL;
		uint16_t mpi_point_bits = 0;
		uint32_t mpi_point_size = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_ECDH_SESSION_KEY;
		}

		mpi_point_bits = ((uint16_t)in[0] << 8) + in[1];
		mpi_point_size = mpi_size(mpi_point_bits);

		if (size < mpi_octets(mpi_point_bits) + 1) // For session key octet count
		{
			return PGP_MALFORMED_ECDH_SESSION_KEY;
		}

		sk = malloc(sizeof(pgp_ecdh_kex) + mpi_point_size);

		if (sk == NULL)
		{
			return PGP_NO_MEMORY;
		}

		// MPI of EC point
		sk->ephemeral_point = mpi_init(PTR_OFFSET(sk, sizeof(pgp_ecdh_kex)), mpi_point_size, mpi_point_bits);
		pos += mpi_read(sk->ephemeral_point, in + pos, size - pos);

		// 1 octet count
		LOAD_8(&sk->encoded_session_key_size, in + pos);
		pos += 1;

		if (size - pos < sk->encoded_session_key_size)
		{
			return PGP_MALFORMED_ECDH_SESSION_KEY;
		}

		// Encrypted session key
		memcpy(sk->encoded_session_key, in + pos, sk->encoded_session_key_size);
		pos += sk->encoded_session_key_size;

		packet->encrypted_session_key = sk;
		packet->encrypted_session_key_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_X25519:
	{
		pgp_x25519_kex *sk = NULL;

		if (size - pos < 33)
		{
			return PGP_MALFORMED_X25519_SESSION_KEY;
		}

		sk = malloc(sizeof(pgp_x25519_kex));

		if (sk == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(sk, 0, sizeof(pgp_x25519_kex));

		// 32 octets of ephemeral key
		memcpy(sk->ephemeral_key, in + pos, 32);
		pos += 32;

		// 1 octet count
		LOAD_8(&sk->octet_count, in + pos);
		pos += 1;

		if (size - pos < sk->octet_count)
		{
			return PGP_MALFORMED_X25519_SESSION_KEY;
		}

		if (packet->version == PGP_PKESK_V3)
		{
			// 1 octet algorithm id
			LOAD_8(&sk->symmetric_key_algorithm_id, in + pos);
			pos += 1;
		}

		// Encrypted session key
		byte_t encrypted_session_key_size = sk->octet_count - (packet->version == PGP_PKESK_V3 ? 1 : 0);

		memcpy(sk->encrypted_session_key, in + pos, encrypted_session_key_size);
		pos += encrypted_session_key_size;

		packet->encrypted_session_key = sk;
		packet->encrypted_session_key_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_X448:
	{
		pgp_x448_kex *sk = NULL;

		if (size - pos < 57)
		{
			return PGP_MALFORMED_X448_SESSION_KEY;
		}

		sk = malloc(sizeof(pgp_x448_kex));

		if (sk == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(sk, 0, sizeof(pgp_x448_kex));

		// 56 octets of ephemeral key
		memcpy(sk->ephemeral_key, in + pos, 56);
		pos += 32;

		// 1 octet count
		LOAD_8(&sk->octet_count, in + pos);
		pos += 1;

		if (size - pos < sk->octet_count)
		{
			return PGP_MALFORMED_X448_SESSION_KEY;
		}

		if (packet->version == PGP_PKESK_V3)
		{
			// 1 octet algorithm id
			LOAD_8(&sk->symmetric_key_algorithm_id, in + pos);
			pos += 1;
		}

		// Encrypted session key
		byte_t encrypted_session_key_size = sk->octet_count - (packet->version == PGP_PKESK_V3 ? 1 : 0);

		memcpy(sk->encrypted_session_key, in + pos, encrypted_session_key_size);
		pos += encrypted_session_key_size;

		packet->encrypted_session_key = sk;
		packet->encrypted_session_key_octets = pos;

		return PGP_SUCCESS;
	}
	default:
		pgp_unknown_kex *sk = malloc(size);

		if (sk == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memcpy(sk->encrypted_session_key, data, size);
		packet->encrypted_session_key_octets = size;

		return PGP_SUCCESS;
	}
}

static uint32_t pgp_session_key_write(pgp_pkesk_packet *packet, void *ptr, uint32_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	{
		// MPI of (m^e) mod n
		pgp_rsa_kex *sk = packet->encrypted_session_key;
		return mpi_write(sk->c, out, size);
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		// MPI of (m^e) mod n
		pgp_elgamal_kex *sk = packet->encrypted_session_key;

		pos += mpi_write(sk->r, out + pos, size - pos);
		pos += mpi_write(sk->s, out + pos, size - pos);

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_kex *sk = packet->encrypted_session_key;

		// MPI of EC point
		pos += mpi_write(sk->ephemeral_point, out + pos, size - pos);

		// 1 octet count
		LOAD_8(out + pos, &sk->encoded_session_key_size);
		pos += 1;

		// Encrypted session key
		memcpy(out + pos, sk->encoded_session_key, sk->encoded_session_key_size);
		pos += sk->encoded_session_key_size;

		return pos;
	}
	case PGP_X25519:
	{
		pgp_x25519_kex *sk = packet->encrypted_session_key;

		// 32 octets of ephemeral key
		memcpy(out + pos, sk->ephemeral_key, 32);
		pos += 32;

		// 1 octet count
		LOAD_8(out + pos, &sk->octet_count);
		pos += 1;

		if (packet->version == PGP_PKESK_V3)
		{
			// 1 octet algorithm id
			LOAD_8(out + pos, &sk->symmetric_key_algorithm_id);
			pos += 1;
		}

		// Encrypted session key
		byte_t encrypted_session_key_size = sk->octet_count - (packet->version == PGP_PKESK_V3 ? 1 : 0);

		memcpy(out + pos, sk->encrypted_session_key, encrypted_session_key_size);
		pos += encrypted_session_key_size;

		return pos;
	}
	case PGP_X448:
	{
		pgp_x448_kex *sk = packet->encrypted_session_key;

		// 56 octets of ephemeral key
		memcpy(out + pos, sk->ephemeral_key, 56);
		pos += 32;

		// 1 octet count
		LOAD_8(out + pos, &sk->octet_count);
		pos += 1;

		if (packet->version == PGP_PKESK_V3)
		{
			// 1 octet algorithm id
			LOAD_8(out + pos, &sk->symmetric_key_algorithm_id);
			pos += 1;
		}

		// Encrypted session key
		byte_t encrypted_session_key_size = sk->octet_count - (packet->version == PGP_PKESK_V3 ? 1 : 0);

		memcpy(out + pos, sk->encrypted_session_key, encrypted_session_key_size);
		pos += encrypted_session_key_size;

		return pos;
	}
	default:
		return 0;
	}
}

static uint16_t get_kex_octets(pgp_public_key_algorithms public_key_algorithm_id, void *kex_data)
{
	switch (public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_ENCRYPT_OR_SIGN:
	{
		pgp_rsa_kex *kex = kex_data;

		return mpi_octets(kex->c->bits);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_kex *kex = kex_data;

		return mpi_octets(kex->r->bits) + mpi_octets(kex->s->bits);
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_kex *kex = kex_data;

		return mpi_octets(kex->ephemeral_point->bits) + 1 + kex->encoded_session_key_size;
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_kex *kex = kex_data;

		return 32 + 1 + kex->octet_count;
	}
	break;
	case PGP_X448:
	{
		pgp_x25519_kex *kex = kex_data;

		return 56 + 1 + kex->octet_count;
	}
	break;
	default:
		return 0;
	}
}

static void pgp_pkesk_packet_encode_header(pgp_pkesk_packet *packet)
{
	uint32_t body_size = 0;

	if (packet->version == PGP_PKESK_V6)
	{
		// A 1-octet version number with value 6.
		// A 1-octet length of below 2 fields
		// (Optional) A 1-octet key version.
		// (Optional) A 20/32-octet key fingerprint
		// A 1-octet public key algorithm.
		// Session key

		body_size = 1 + 1 + 1 + packet->key_octet_count + packet->encrypted_session_key_octets;
		packet->header = pgp_packet_header_encode(PGP_HEADER, PGP_PKESK, 0, body_size);
	}

	if (packet->version == PGP_PKESK_V3)
	{
		// A 1-octet version number with value 3.
		// A 8-octet key ID
		// A 1-octet public key algorithm.
		// Session key

		body_size = 1 + 8 + 1 + packet->encrypted_session_key_octets;
		packet->header = pgp_packet_header_encode(PGP_LEGACY_HEADER, PGP_PKESK, 0, body_size);
	}
}

pgp_error_t pgp_pkesk_packet_new(pgp_pkesk_packet **packet, byte_t version)
{
	pgp_pkesk_packet *session = NULL;

	if (version != PGP_PKESK_V6 && version != PGP_PKESK_V3)
	{
		return PGP_UNKNOWN_PUBLIC_SESSION_PACKET_VERSION;
	}

	session = malloc(sizeof(pgp_pkesk_packet));

	if (session == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(session, 0, sizeof(pgp_pkesk_packet));

	pgp_pkesk_packet_encode_header(session);
	session->version = version;

	*packet = session;

	return PGP_SUCCESS;
}

void pgp_pkesk_packet_delete(pgp_pkesk_packet *packet)
{
	free(packet->encrypted_session_key);
	free(packet);
}

pgp_error_t pgp_pkesk_packet_session_key_encrypt(pgp_pkesk_packet *packet, pgp_key_packet *key, byte_t anonymous,
												 byte_t session_key_algorithm_id, void *session_key, byte_t session_key_size)
{
	pgp_error_t status = 0;
	byte_t key_size = pgp_symmetric_cipher_key_size(session_key_algorithm_id);
	byte_t symmetric_key_algorithm_id = packet->version == PGP_PKESK_V6 ? 0 : session_key_algorithm_id;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	if (pgp_symmetric_cipher_algorithm_validate(session_key_algorithm_id) == 0)
	{
		return PGP_UNKNOWN_CIPHER_ALGORITHM;
	}

	if (session_key_size != key_size)
	{
		return PGP_INVALID_CIPHER_KEY_SIZE;
	}

	packet->key_version = key->version;
	packet->public_key_algorithm_id = key->public_key_algorithm_id;
	packet->symmetric_key_algorithm_id = session_key_algorithm_id;

	status = pgp_key_fingerprint(key, fingerprint, &fingerprint_size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	if (anonymous == 0)
	{
		packet->key_octet_count = 1;

		if (packet->version == PGP_PKESK_V6)
		{
			memcpy(packet->key_fingerprint, fingerprint, fingerprint_size);
			packet->key_octet_count += fingerprint_size;
		}
		else
		{
			packet->key_octet_count += pgp_key_id_from_fingerprint(key->version, packet->key_id, fingerprint, fingerprint_size);
		}
	}

	// Encrypt
	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_ENCRYPT_OR_SIGN:
	{
		status = pgp_rsa_kex_encrypt((pgp_rsa_kex **)&packet->encrypted_session_key, key->key, symmetric_key_algorithm_id, session_key,
									 session_key_size);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		// TODO
	}
	break;
	case PGP_ECDH:
	{
		status = pgp_ecdh_kex_encrypt((pgp_ecdh_kex **)&packet->encrypted_session_key, key->key, symmetric_key_algorithm_id, fingerprint,
									  fingerprint_size, session_key, session_key_size);
	}
	break;
	case PGP_X25519:
	{
		status = pgp_x25519_kex_encrypt((pgp_x25519_kex **)&packet->encrypted_session_key, key->key, symmetric_key_algorithm_id,
										session_key, session_key_size);
	}
	break;
	case PGP_X448:
	{
		status = pgp_x448_kex_encrypt((pgp_x448_kex **)&packet->encrypted_session_key, key->key, symmetric_key_algorithm_id, session_key,
									  session_key_size);
	}
	break;
	default:
		return PGP_UNSUPPORTED_KEY_EXCHANGE_ALGORITHM;
	}

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	packet->encrypted_session_key_octets = get_kex_octets(packet->public_key_algorithm_id, packet->encrypted_session_key);
	pgp_pkesk_packet_encode_header(packet);

	return PGP_SUCCESS;
}

pgp_error_t pgp_pkesk_packet_session_key_decrypt(pgp_pkesk_packet *packet, pgp_key_packet *key, void *session_key, byte_t *session_key_size)
{
	pgp_error_t status = 0;
	byte_t *symmetric_key_algorithm_id = NULL;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	status = pgp_key_fingerprint(key, fingerprint, &fingerprint_size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Check the algorithm id
	if (packet->public_key_algorithm_id != key->public_key_algorithm_id)
	{
		return PGP_INCORRECT_KEY_SELECTION;
	}

	if (packet->version == PGP_PKESK_V3)
	{
		symmetric_key_algorithm_id = &packet->symmetric_key_algorithm_id;
	}

	// Decrypt
	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_ENCRYPT_OR_SIGN:
		status = pgp_rsa_kex_decrypt(packet->encrypted_session_key, key->key, symmetric_key_algorithm_id, session_key, session_key_size);
		break;
	case PGP_ECDH:
		status = pgp_ecdh_kex_decrypt(packet->encrypted_session_key, key->key, symmetric_key_algorithm_id, fingerprint, fingerprint_size,
									  session_key, session_key_size);
		break;
	case PGP_X25519:
		status = pgp_x25519_kex_decrypt(packet->encrypted_session_key, key->key, symmetric_key_algorithm_id, session_key, session_key_size);
		break;
	case PGP_X448:
		status = pgp_x448_kex_decrypt(packet->encrypted_session_key, key->key, symmetric_key_algorithm_id, session_key, session_key_size);
		break;
	default:
		return PGP_UNSUPPORTED_KEY_EXCHANGE_ALGORITHM;
	}

	return status;
}

static pgp_error_t pgp_pkesk_packet_read_body(pgp_pkesk_packet *packet, buffer_t *buffer)
{
	// 1 octet version
	CHECK_READ(read8(buffer, &packet->version), PGP_MALFORMED_PUBLIC_SESSION_PACKET);

	if (packet->version == PGP_PKESK_V6)
	{
		// 1 octet anonymous flag
		CHECK_READ(read8(buffer, &packet->key_octet_count), PGP_MALFORMED_PUBLIC_SESSION_PACKET);

		if (packet->key_octet_count > 0)
		{
			// 1 octet key version
			CHECK_READ(read8(buffer, &packet->key_version), PGP_MALFORMED_PUBLIC_SESSION_PACKET);

			if ((packet->key_octet_count - 1) == PGP_KEY_V6_FINGERPRINT_SIZE) // V6 or V5 key
			{
				CHECK_READ(readn(buffer, packet->key_fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE), PGP_MALFORMED_PUBLIC_SESSION_PACKET);
			}
			else if ((packet->key_octet_count - 1) == PGP_KEY_V4_FINGERPRINT_SIZE) // V4 key
			{
				CHECK_READ(readn(buffer, packet->key_fingerprint, PGP_KEY_V4_FINGERPRINT_SIZE), PGP_MALFORMED_PUBLIC_SESSION_PACKET);
			}
			else
			{
				return PGP_MALFORMED_PUBLIC_SESSION_PACKET_COUNT;
			}
		}
	}
	else if (packet->version == PGP_PKESK_V3)
	{
		// A 8-octet Key ID of the signer.
		CHECK_READ(read64(buffer, packet->key_id), PGP_MALFORMED_PUBLIC_SESSION_PACKET);
	}
	else
	{
		// Unknown version.
		return PGP_UNKNOWN_PUBLIC_SESSION_PACKET_VERSION;
	}

	// 1 octet public-key algorithm
	CHECK_READ(read8(buffer, &packet->public_key_algorithm_id), PGP_MALFORMED_PUBLIC_SESSION_PACKET);

	// Read the encrypted session key
	return pgp_session_key_read(packet, buffer->data + buffer->pos, buffer->size - buffer->pos);
}

pgp_error_t pgp_pkesk_packet_read_with_header(pgp_pkesk_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_pkesk_packet *session = NULL;

	session = malloc(sizeof(pgp_pkesk_packet));

	if (session == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(session, 0, sizeof(pgp_pkesk_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	session->header = *header;

	// Read the body
	error = pgp_pkesk_packet_read_body(session, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_pkesk_packet_delete(session);
		return error;
	}

	*packet = session;

	return error;
}

pgp_error_t pgp_pkesk_packet_read(pgp_pkesk_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_PKESK)
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

	return pgp_pkesk_packet_read_with_header(packet, &header, data);
}

static size_t pgp_pkesk_packet_v3_write(pgp_pkesk_packet *packet, void *ptr, size_t size)
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

	// A 8-octet key ID
	LOAD_64(out + pos, &packet->key_id);
	pos += 8;

	// 1 octet public-key algorithm
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	pos += pgp_session_key_write(packet, out + pos, size - pos);

	return pos;
}

static size_t pgp_pkesk_packet_v6_write(pgp_pkesk_packet *packet, void *ptr, size_t size)
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

	// 1 octet octet count flag
	LOAD_8(out + pos, &packet->key_octet_count);
	pos += 1;

	if (packet->key_octet_count > 0)
	{
		// 1 octet key version
		LOAD_8(out + pos, &packet->key_version);
		pos += 1;

		if ((packet->key_octet_count - 1) == 32) // V6 key
		{
			memcpy(out + pos, packet->key_fingerprint, 32);
			pos += 32;
		}
		else // V4 key
		{
			memcpy(out + pos, packet->key_fingerprint, 20);
			pos += 20;
		}
	}

	// 1 octet public-key algorithm
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	pos += pgp_session_key_write(packet, out + pos, size - pos);

	return pos;
}

size_t pgp_pkesk_packet_write(pgp_pkesk_packet *packet, void *ptr, size_t size)
{
	switch (packet->version)
	{
	case PGP_PKESK_V3:
		return pgp_pkesk_packet_v3_write(packet, ptr, size);
	case PGP_PKESK_V6:
		return pgp_pkesk_packet_v6_write(packet, ptr, size);
	default:
		return 0;
	}
}

static void pgp_skesk_packet_encode_header(pgp_skesk_packet *packet)
{
	uint32_t body_size = 0;

	if (packet->version >= PGP_SKESK_V5)
	{
		// A 1-octet version number with value 5,6.
		// A 1-octet count of below 5 fields.
		// A 1-octet symmetric key algorithm.
		// A 1-octet AEAD algorithm.
		// A 1-octet count of below field.
		// A S2K specifier
		// IV
		// Encrypted session key.
		// Authetication key tag.

		body_size = 1 + 1 + 1 + 1 + 1 + pgp_s2k_octets(&packet->s2k) + packet->iv_size + packet->session_key_size + packet->tag_size;
		packet->header = pgp_packet_header_encode(PGP_HEADER, PGP_SKESK, 0, body_size);
	}
	else
	{
		// A 1-octet version number with value 4.
		// A 1-octet symmetric key algorithm.
		// A S2K specifier
		// (Optional) Encrypted Session key

		body_size = 1 + 1 + pgp_s2k_octets(&packet->s2k) + packet->session_key_size;
		packet->header = pgp_packet_header_encode(PGP_LEGACY_HEADER, PGP_SKESK, 0, body_size);
	}
}

pgp_error_t pgp_skesk_packet_new(pgp_skesk_packet **packet, byte_t version, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id,
								 pgp_s2k *s2k)
{
	pgp_skesk_packet *session = NULL;

	if (version != PGP_SKESK_V4 && version != PGP_SKESK_V5 && version != PGP_SKESK_V6)
	{
		return PGP_UNKNOWN_SYMMETRIC_SESSION_PACKET_VERSION;
	}

	if (pgp_symmetric_cipher_algorithm_validate(symmetric_key_algorithm_id) == 0)
	{
		return PGP_UNKNOWN_CIPHER_ALGORITHM;
	}

	if (version == PGP_SKESK_V6 || version == PGP_SKESK_V5)
	{
		// Unsupported ciphers for AEAD.
		if (symmetric_key_algorithm_id == PGP_PLAINTEXT || symmetric_key_algorithm_id == PGP_BLOWFISH ||
			symmetric_key_algorithm_id == PGP_TDES || symmetric_key_algorithm_id == PGP_IDEA)
		{
			return PGP_INVALID_AEAD_CIPHER_PAIR;
		}

		if (pgp_aead_algorithm_validate(aead_algorithm_id) == 0)
		{
			return PGP_UNKNOWN_AEAD_ALGORITHM;
		}
	}

	session = malloc(sizeof(pgp_skesk_packet));

	if (session == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(session, 0, sizeof(pgp_skesk_packet));

	session->version = version;
	session->symmetric_key_algorithm_id = symmetric_key_algorithm_id;

	if (version == PGP_SKESK_V6 || version == PGP_SKESK_V5)
	{
		session->aead_algorithm_id = aead_algorithm_id;
		session->tag_size = PGP_AEAD_TAG_SIZE;
	}
	else
	{
		session->aead_algorithm_id = 0;
		session->iv_size = 0;
		session->tag_size = 0;
	}

	memcpy(&session->s2k, s2k, sizeof(pgp_s2k));
	pgp_skesk_packet_encode_header(session);

	*packet = session;

	return PGP_SUCCESS;
}

void pgp_skesk_packet_delete(pgp_skesk_packet *packet)
{
	free(packet);
}

static pgp_error_t pgp_skesk_packet_session_key_v4_encrypt(pgp_skesk_packet *packet, void *password, byte_t password_size,
														   void *session_key, byte_t session_key_size)
{
	pgp_error_t status = 0;

	byte_t key[32] = {0};
	byte_t buffer[48] = {0};
	byte_t zero_iv[16] = {0};

	byte_t iv_size = pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id);

	if (session_key == NULL || session_key_size == 0)
	{
		// No crypto operations to do here.
		pgp_skesk_packet_encode_header(packet);
	}
	else
	{
		status = pgp_s2k_hash(&packet->s2k, password, password_size, key, session_key_size);

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		// Encrypt symmetric algorithm id followed by session key
		buffer[0] = packet->symmetric_key_algorithm_id;
		memcpy(PTR_OFFSET(buffer, 1), session_key, session_key_size);

		status = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, key, session_key_size, zero_iv, iv_size, buffer, session_key_size + 1,
								 packet->session_key, session_key_size + 1);
		packet->session_key_size = session_key_size + 1;

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		pgp_skesk_packet_encode_header(packet);
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_skesk_packet_session_key_v4_decrypt(pgp_skesk_packet *packet, void *password, byte_t password_size,
														   void *session_key, byte_t *session_key_size)
{
	pgp_error_t status = 0;

	byte_t key[32] = {0};
	byte_t buffer[48] = {0};
	byte_t zero_iv[16] = {0};

	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	byte_t iv_size = pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id);

	if (packet->session_key_size == 0)
	{
		status = pgp_s2k_hash(&packet->s2k, password, password_size, session_key, key_size);

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		*session_key_size = key_size;
	}
	else
	{
		if ((packet->session_key_size - 1) > *session_key_size)
		{
			return PGP_BUFFER_TOO_SMALL;
		}

		status = pgp_s2k_hash(&packet->s2k, password, password_size, key, key_size);

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		// Decrypt the session key
		status = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, key, key_size, zero_iv, iv_size, packet->session_key,
								 packet->session_key_size, buffer, 48);

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		// Set the new algorithm
		packet->symmetric_key_algorithm_id = buffer[0];
		*session_key_size = packet->session_key_size - 1;

		memcpy(session_key, PTR_OFFSET(buffer, 1), packet->session_key_size - 1);
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_skesk_packet_session_key_v5_v6_encrypt(pgp_skesk_packet *packet, void *password, byte_t password_size, void *iv,
															  byte_t iv_size, void *session_key, byte_t session_key_size)
{
	pgp_error_t status = 0;

	byte_t ik[32] = {0};
	byte_t sk[32] = {0};
	byte_t info[4] = {0};

	byte_t buffer[64] = {0};
	byte_t *key = NULL;

	if (iv_size != pgp_aead_iv_size(packet->aead_algorithm_id))
	{
		return PGP_INVALID_AEAD_IV_SIZE;
	}

	info[0] = packet->header.tag;
	info[1] = packet->version;
	info[2] = packet->symmetric_key_algorithm_id;
	info[3] = packet->aead_algorithm_id;

	packet->iv_size = iv_size;
	packet->session_key_size = session_key_size;

	memcpy(packet->iv, iv, iv_size);

	status = pgp_s2k_hash(&packet->s2k, password, password_size, ik, packet->session_key_size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	if (packet->version == PGP_SKESK_V6)
	{
		pgp_hkdf(PGP_SHA2_256, ik, 16, NULL, 0, info, 4, sk, packet->session_key_size);
		key = sk;
	}
	else // packet->version == PGP_SKESK_V5
	{
		key = ik;
	}

	status = pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, key, packet->session_key_size, packet->iv,
							  packet->iv_size, info, 4, session_key, session_key_size, buffer, 64);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Copy the aead encrypted output
	memcpy(packet->session_key, buffer, packet->session_key_size);
	memcpy(packet->tag, PTR_OFFSET(buffer, packet->session_key_size), packet->tag_size);

	// Fill up the header now, we have enough information.
	pgp_skesk_packet_encode_header(packet);

	return PGP_SUCCESS;
}

static pgp_error_t pgp_skesk_packet_session_key_v5_v6_decrypt(pgp_skesk_packet *packet, void *password, byte_t password_size,
															  void *session_key, byte_t *session_key_size)
{
	pgp_error_t status = 0;

	byte_t ik[32] = {0};
	byte_t sk[32] = {0};
	byte_t info[4] = {0};

	byte_t buffer[64] = {0};
	byte_t temp[64] = {0};

	byte_t *key = NULL;

	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	info[0] = packet->header.tag;
	info[1] = packet->version;
	info[2] = packet->symmetric_key_algorithm_id;
	info[3] = packet->aead_algorithm_id;

	if (*session_key_size < packet->session_key_size)
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	status = pgp_s2k_hash(&packet->s2k, password, password_size, ik, key_size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	if (packet->version == PGP_SKESK_V6)
	{
		pgp_hkdf(PGP_SHA2_256, ik, 16, NULL, 0, info, 4, sk, packet->session_key_size);
		key = sk;
	}
	else // packet->version == PGP_SKESK_V5
	{
		key = ik;
	}

	// Store the encrypted session key and tag together
	memcpy(buffer, packet->session_key, packet->session_key_size);
	memcpy(PTR_OFFSET(buffer, packet->session_key_size), packet->tag, packet->tag_size);

	status = pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, key, key_size, packet->iv, packet->iv_size,
							  info, 4, buffer, packet->session_key_size + packet->tag_size, temp, 64);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Copy the session key to the output
	memcpy(session_key, temp, packet->session_key_size);
	*session_key_size = packet->session_key_size;

	return PGP_SUCCESS;
}

pgp_error_t pgp_skesk_packet_session_key_encrypt(pgp_skesk_packet *packet, void *password, byte_t password_size, void *iv, byte_t iv_size,
												 void *session_key, byte_t session_key_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	switch (packet->version)
	{
	case PGP_SKESK_V6:
	case PGP_SKESK_V5:
	{
		if (key_size != session_key_size)
		{
			return PGP_INVALID_CIPHER_KEY_SIZE;
		}

		return pgp_skesk_packet_session_key_v5_v6_encrypt(packet, password, password_size, iv, iv_size, session_key, session_key_size);
	}
	case PGP_SKESK_V4:
		return pgp_skesk_packet_session_key_v4_encrypt(packet, password, password_size, session_key, session_key_size);
	default:
		return PGP_UNKNOWN_SYMMETRIC_SESSION_PACKET_VERSION;
	}

	// Unreachable
	return PGP_INTERNAL_BUG;
}

pgp_error_t pgp_skesk_packet_session_key_decrypt(pgp_skesk_packet *packet, void *password, byte_t password_size, void *session_key,
												 byte_t *session_key_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	if (*session_key_size < key_size)
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	switch (packet->version)
	{
	case PGP_SKESK_V6:
	case PGP_SKESK_V5:
		return pgp_skesk_packet_session_key_v5_v6_decrypt(packet, password, password_size, session_key, session_key_size);
	case PGP_SKESK_V4:
		return pgp_skesk_packet_session_key_v4_decrypt(packet, password, password_size, session_key, session_key_size);
	default:
		return PGP_UNKNOWN_SYMMETRIC_SESSION_PACKET_VERSION;
	}

	// Unreachable
	return PGP_INTERNAL_BUG;
}

static pgp_error_t pgp_skesk_packet_read_body(pgp_skesk_packet *packet, buffer_t *buffer)
{
	// 1 octet version
	CHECK_READ(read8(buffer, &packet->version), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);

	if (packet->version == PGP_SKESK_V6 || packet->version == PGP_SKESK_V5)
	{
		uint32_t result = 0;
		byte_t count = 0;
		byte_t s2k_size = 0;

		// A 1-octet count of below 5 fields
		CHECK_READ(read8(buffer, &count), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);

		// 1 octet symmetric key algorithm
		CHECK_READ(read8(buffer, &packet->symmetric_key_algorithm_id), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);

		// 1 octet AEAD algorithm
		CHECK_READ(read8(buffer, &packet->aead_algorithm_id), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);

		// 1 octet S2K size
		CHECK_READ(read8(buffer, &s2k_size), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);

		// S2K specifier
		if ((buffer->pos + s2k_size) > buffer->size)
		{
			return PGP_MALFORMED_S2K_SIZE;
		}

		result = pgp_s2k_read(&packet->s2k, buffer->data + buffer->pos, s2k_size);

		if (result == 0)
		{
			return PGP_UNKNOWN_S2K_SPECIFIER;
		}

		if (result != s2k_size)
		{
			return PGP_MALFORMED_S2K_SIZE;
		}

		buffer->pos += s2k_size;
		packet->iv_size = count - (1 + 1 + 1 + s2k_size);

		// IV
		if (packet->iv_size != pgp_aead_iv_size(packet->aead_algorithm_id))
		{
			return PGP_MALFORMED_SYMMETRIC_SESSION_PACKET_COUNT;
		}

		CHECK_READ(readn(buffer, packet->iv, packet->iv_size), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);

		// Encrypted session key.
		packet->session_key_size = buffer->size - buffer->pos - PGP_AEAD_TAG_SIZE;
		CHECK_READ(readn(buffer, packet->session_key, packet->session_key_size), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);

		// Authetication key tag.
		packet->tag_size = PGP_AEAD_TAG_SIZE;
		CHECK_READ(readn(buffer, packet->tag, packet->tag_size), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);
	}
	else if (packet->version == PGP_SKESK_V4)
	{
		uint32_t result = 0;

		// 1 octet symmetric key algorithm
		CHECK_READ(read8(buffer, &packet->symmetric_key_algorithm_id), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);

		// S2K specifier
		result = pgp_s2k_read(&packet->s2k, buffer->data + buffer->pos, buffer->size - buffer->pos);

		if (result == 0)
		{
			return PGP_UNKNOWN_S2K_SPECIFIER;
		}

		buffer->pos += result;

		// (Optional) Session key
		packet->session_key_size = buffer->size - buffer->pos;

		if (packet->session_key_size > 0)
		{
			CHECK_READ(readn(buffer, packet->session_key, packet->session_key_size), PGP_MALFORMED_SYMMETRIC_SESSION_PACKET);
		}
	}
	else
	{
		// Unknown version.
		return PGP_UNKNOWN_SYMMETRIC_SESSION_PACKET_VERSION;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_skesk_packet_read_with_header(pgp_skesk_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_skesk_packet *session = NULL;

	session = malloc(sizeof(pgp_skesk_packet));

	if (session == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(session, 0, sizeof(pgp_skesk_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	session->header = *header;

	// Read the body
	error = pgp_skesk_packet_read_body(session, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_skesk_packet_delete(session);
		return error;
	}

	*packet = session;

	return error;
}

pgp_error_t pgp_skesk_packet_read(pgp_skesk_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_SKESK)
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

	return pgp_skesk_packet_read_with_header(packet, &header, data);
}

static size_t pgp_skesk_packet_v4_write(pgp_skesk_packet *packet, void *ptr, size_t size)
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

	// 1 octet symmetric key algorithm
	LOAD_8(out + pos, &packet->symmetric_key_algorithm_id);
	pos += 1;

	// S2K specifier
	pos += pgp_s2k_write(&packet->s2k, out + pos);

	// (Optional) Session key
	if (packet->session_key_size > 0)
	{
		memcpy(out + pos, packet->session_key, packet->session_key_size);
		pos += packet->session_key_size;
	}

	return pos;
}

static size_t pgp_skesk_packet_v5_v6_write(pgp_skesk_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	byte_t s2k_size = 0;
	size_t pos = 0;

	s2k_size = pgp_s2k_octets(&packet->s2k);

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// A 1-octet count of below 5 fields
	byte_t count = 1 + 1 + 1 + s2k_size + packet->iv_size;

	LOAD_8(out + pos, &count);
	pos += 1;

	// 1 octet symmetric key algorithm
	LOAD_8(out + pos, &packet->symmetric_key_algorithm_id);
	pos += 1;

	// 1 octet AEAD algorithm
	LOAD_8(out + pos, &packet->aead_algorithm_id);
	pos += 1;

	// 1 octet S2K size
	LOAD_8(out + pos, &s2k_size);
	pos += 1;

	// S2K specifier
	pos += pgp_s2k_write(&packet->s2k, out + pos);

	// IV
	memcpy(out + pos, packet->iv, packet->iv_size);
	pos += packet->iv_size;

	// Encrypted session key.
	memcpy(out + pos, packet->session_key, packet->session_key_size);
	pos += packet->session_key_size;

	// Authetication key tag.
	memcpy(out + pos, packet->tag, packet->tag_size);
	pos += packet->tag_size;

	return pos;
}

size_t pgp_skesk_packet_write(pgp_skesk_packet *packet, void *ptr, size_t size)
{
	switch (packet->version)
	{
	case PGP_SKESK_V4:
		return pgp_skesk_packet_v4_write(packet, ptr, size);
	case PGP_SKESK_V6:
		return pgp_skesk_packet_v5_v6_write(packet, ptr, size);
	default:
		return 0;
	}
}
