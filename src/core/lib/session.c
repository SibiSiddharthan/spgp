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

static uint32_t pgp_session_key_read(pgp_pkesk_packet *packet, void *ptr, uint32_t size)
{
	byte_t *in = ptr;
	size_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	{
		// MPI of (m^e) mod n
		pgp_rsa_kex *sk = NULL;
		uint16_t mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return 0;
		}

		sk = malloc(sizeof(pgp_rsa_kex) + mpi_size(mpi_bits));

		if (sk == NULL)
		{
			return 0;
		}

		sk->c = mpi_init(PTR_OFFSET(sk, sizeof(pgp_rsa_kex)), mpi_size(mpi_bits), mpi_bits);
		pos += mpi_read(sk->c, in, size);

		packet->encrypted_session_key = sk;

		return pos;
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

		mpi_r_bits = ((uint16_t)in[0] << 8) + in[1];
		offset = mpi_octets(mpi_r_bits);
		mpi_s_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];

		mpi_r_size = mpi_size(mpi_r_bits);
		mpi_s_size = mpi_size(mpi_s_bits);

		if (size < (mpi_octets(mpi_r_bits) + mpi_octets(mpi_s_bits)))
		{
			return 0;
		}

		sk = malloc(sizeof(pgp_elgamal_kex) + mpi_r_size + mpi_s_size);

		if (sk == NULL)
		{
			return 0;
		}

		sk->r = mpi_init(PTR_OFFSET(sk, sizeof(pgp_elgamal_kex)), mpi_r_size, mpi_r_bits);
		sk->s = mpi_init(PTR_OFFSET(sk, sizeof(pgp_elgamal_kex) + mpi_r_size), mpi_s_size, mpi_s_bits);

		pos += mpi_read(sk->r, in + pos, size - pos);
		pos += mpi_read(sk->s, in + pos, size - pos);

		packet->encrypted_session_key = sk;

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_kex *sk = NULL;
		uint16_t mpi_point_bits = ((uint16_t)in[0] << 8) + in[1];
		uint32_t mpi_point_size = mpi_size(mpi_point_bits);

		if (size < mpi_octets(mpi_point_bits))
		{
			return 0;
		}

		sk = malloc(sizeof(pgp_ecdh_kex) + mpi_point_size);

		if (sk == NULL)
		{
			return 0;
		}

		// MPI of EC point
		sk->ephemeral_point = mpi_init(PTR_OFFSET(sk, sizeof(pgp_ecdh_kex)), mpi_point_size, mpi_point_bits);
		pos += mpi_read(sk->ephemeral_point, in + pos, size - pos);

		// 1 octet count
		LOAD_8(&sk->encoded_session_key_size, in + pos);
		pos += 1;

		// Encrypted session key
		memcpy(sk->encoded_session_key, in + pos, sk->encoded_session_key_size);
		pos += sk->encoded_session_key_size;

		packet->encrypted_session_key = sk;

		return pos;
	}
	case PGP_X25519:
	{
		pgp_x25519_kex *sk = malloc(sizeof(pgp_x25519_kex));

		if (sk == NULL)
		{
			return 0;
		}

		memset(sk, 0, sizeof(pgp_x25519_kex));

		// 32 octets of ephemeral key
		memcpy(sk->ephemeral_key, in + pos, 32);
		pos += 32;

		// 1 octet count
		LOAD_8(&sk->octet_count, in + pos);
		pos += 1;

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

		return pos;
	}
	case PGP_X448:
	{
		pgp_x448_kex *sk = malloc(sizeof(pgp_x448_kex));

		if (sk == NULL)
		{
			return 0;
		}

		memset(sk, 0, sizeof(pgp_x448_kex));

		// 56 octets of ephemeral key
		memcpy(sk->ephemeral_key, in + pos, 56);
		pos += 32;

		// 1 octet count
		LOAD_8(&sk->octet_count, in + pos);
		pos += 1;

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

		return pos;
	}
	default:
		return 0;
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

		body_size = 1 + 1 + 1 + packet->key_octet_count + packet->encrypted_session_key_size;
		packet->header = pgp_encode_packet_header(PGP_HEADER, PGP_PKESK, body_size);
	}

	if (packet->version == PGP_PKESK_V3)
	{
		// A 1-octet version number with value 3.
		// A 8-octet key ID
		// A 1-octet public key algorithm.
		// Session key

		body_size = 1 + 8 + 1 + packet->encrypted_session_key_size;
		packet->header = pgp_encode_packet_header(PGP_LEGACY_HEADER, PGP_PKESK, body_size);
	}
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

pgp_pkesk_packet *pgp_pkesk_packet_new(byte_t version, byte_t public_key_algorithm_id, byte_t session_key_algorithm_id)
{
	pgp_pkesk_packet *packet = NULL;

	if (version != PGP_PKESK_V6 && version != PGP_PKESK_V3)
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_pkesk_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_pkesk_packet));

	packet->version = version;
	packet->public_key_algorithm_id = public_key_algorithm_id;
	packet->symmetric_key_algorithm_id = session_key_algorithm_id;

	pgp_pkesk_packet_encode_header(packet);

	return packet;
}

void pgp_pkesk_packet_delete(pgp_pkesk_packet *packet)
{
	free(packet->encrypted_session_key);
	free(packet);
}

pgp_pkesk_packet *pgp_pkesk_packet_session_key_encrypt(pgp_pkesk_packet *packet, pgp_key_packet *key, void *session_key,
													   size_t session_key_size, byte_t anonymous)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	byte_t symmetric_key_algorithm_id = packet->version == PGP_PKESK_V6 ? 0 : packet->symmetric_key_algorithm_id;

	// Check the algorithms
	// if (packet->public_key_algorithm_id != key->public_key_algorithm_id)
	//{
	//	return NULL;
	//}

	if (session_key_size != key_size)
	{
		return NULL;
	}

	packet->key_version = key->version;

	if (anonymous == 0)
	{
		packet->key_octet_count = 1;

		if (packet->version == PGP_PKESK_V6)
		{
			packet->key_octet_count += pgp_key_fingerprint(key, packet->key_fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);
		}
		else
		{
			packet->key_octet_count += pgp_key_id(key, packet->key_id);
		}
	}

	// Encrypt
	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_ENCRYPT_OR_SIGN:
	{
		pgp_rsa_kex *kex = pgp_rsa_kex_encrypt(key->key, symmetric_key_algorithm_id, session_key, session_key_size);
		packet->encrypted_session_key = kex;
		packet->encrypted_session_key_size = mpi_octets(kex->c->bits);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		// packet->encrypted_session_key =
		//	pgp_elgamal_kex_encrypt(public_key->key_data, symmetric_key_algorithm_id, session_key, session_key_size);
		break;
	case PGP_ECDH:
	{
		pgp_ecdh_kex *kex = NULL;
		byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
		byte_t fingerprint_size = 0;

		fingerprint_size = pgp_key_fingerprint(key, fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);
		kex = pgp_ecdh_kex_encrypt(key->key, symmetric_key_algorithm_id, fingerprint, fingerprint_size, session_key, session_key_size);

		packet->encrypted_session_key = kex;
		packet->encrypted_session_key_size = mpi_octets(kex->ephemeral_point->bits) + 1 + kex->encoded_session_key_size;
	}
	break;
	case PGP_X25519:
		packet->encrypted_session_key = pgp_x25519_kex_encrypt(key->key, symmetric_key_algorithm_id, session_key, session_key_size);
		break;
	case PGP_X448:
		packet->encrypted_session_key = pgp_x448_kex_encrypt(key->key, symmetric_key_algorithm_id, session_key, session_key_size);
		break;
	default:
		return NULL;
	}

	if (packet->encrypted_session_key == NULL)
	{
		return NULL;
	}

	// Update the header
	pgp_pkesk_packet_encode_header(packet);

	return packet;
}

uint32_t pgp_pkesk_packet_session_key_decrypt(pgp_pkesk_packet *packet, pgp_key_packet *key, void *session_key, size_t session_key_size)
{
	uint32_t result = 0;

	byte_t symmetric_key_algorithm_id = 0;

	// Check whether key is corret
	if (packet->version == PGP_PKESK_V6)
	{
		byte_t key_fingerprint_size = 0;
		byte_t key_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};

		key_fingerprint_size = pgp_key_fingerprint(key, key_fingerprint, 32);

		if (memcmp(packet->key_fingerprint, key_fingerprint, key_fingerprint_size) != 0)
		{
			return 0;
		}
	}

	if (packet->version == PGP_PKESK_V3)
	{
		byte_t key_id[PGP_KEY_ID_SIZE] = {0};

		pgp_key_id(key, key_id);

		if (memcmp(packet->key_id, key_id, PGP_KEY_ID_SIZE) != 0)
		{
			return 0;
		}
	}

	// Decrypt
	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_ENCRYPT_OR_SIGN:
		result = pgp_rsa_kex_decrypt(packet->encrypted_session_key, key->key, &symmetric_key_algorithm_id, session_key, session_key_size);
		break;
	case PGP_ECDH:
		byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
		byte_t fingerprint_size = 0;

		fingerprint_size = pgp_key_fingerprint(key, fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);
		result = pgp_ecdh_kex_decrypt(packet->encrypted_session_key, key->key, &symmetric_key_algorithm_id, fingerprint, fingerprint_size,
									  session_key, session_key_size);
		break;
	case PGP_X25519:
		result =
			pgp_x25519_kex_decrypt(packet->encrypted_session_key, key->key, &symmetric_key_algorithm_id, session_key, session_key_size);
		break;
	case PGP_X448:
		result = pgp_x448_kex_decrypt(packet->encrypted_session_key, key->key, &symmetric_key_algorithm_id, session_key, session_key_size);
		break;
	default:
		return 0;
	}

	if (result == 0)
	{
		return 0;
	}

	// Assign the symmetric algorithm
	if (packet->version == PGP_PKESK_V3)
	{
		packet->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
	}

	return result;
}

pgp_pkesk_packet *pgp_pkesk_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_pkesk_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_PKESK)
	{
		return NULL;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_pkesk_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	// Copy the header
	packet->header = header;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	if (packet->version == PGP_PKESK_V6)
	{
		// 1 octet anonymous flag
		LOAD_8(&packet->key_octet_count, in + pos);
		pos += 1;

		if (packet->key_octet_count > 0)
		{
			// 1 octet key version
			LOAD_8(&packet->key_version, in + pos);
			pos += 1;

			if ((packet->key_octet_count - 1) == 32) // V6 key
			{
				memcpy(packet->key_fingerprint, in + pos, 32);
				pos += 32;
			}
			else if ((packet->key_octet_count - 1) == 20) // V4 key
			{
				memcpy(packet->key_fingerprint, in + pos, 20);
				pos += 20;
			}
			else
			{
				// Invalid key fingerprint.
				return NULL;
			}
		}
	}
	else if (packet->version == PGP_PKESK_V3)
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

	// 1 octet public-key algorithm
	LOAD_8(&packet->public_key_algorithm_id, in + pos);
	pos += 1;

	pgp_session_key_read(packet, in + pos, packet->header.body_size - (pos - packet->header.header_size));

	return packet;
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
		packet->header = pgp_encode_packet_header(PGP_HEADER, PGP_SKESK, body_size);
	}
	else
	{
		// A 1-octet version number with value 4.
		// A 1-octet symmetric key algorithm.
		// A S2K specifier
		// (Optional) Encrypted Session key

		body_size = 1 + 1 + pgp_s2k_octets(&packet->s2k) + packet->session_key_size;
		packet->header = pgp_encode_packet_header(PGP_LEGACY_HEADER, PGP_SKESK, body_size);
	}
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

static pgp_skesk_packet *pgp_skesk_packet_session_key_v4_encrypt(pgp_skesk_packet *packet, void *password, size_t password_size,
																 void *session_key, size_t session_key_size)
{
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
		pgp_s2k_hash(&packet->s2k, password, password_size, key, session_key_size);

		// Encrypt symmetric algorithm id followed by session key
		buffer[0] = packet->symmetric_key_algorithm_id;
		memcpy(PTR_OFFSET(buffer, 1), session_key, session_key_size);

		pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, key, session_key_size, zero_iv, iv_size, buffer, session_key_size + 1,
						packet->session_key, session_key_size + 1);

		packet->session_key_size = session_key_size + 1;

		pgp_skesk_packet_encode_header(packet);
	}

	return packet;
}

static uint32_t pgp_skesk_packet_session_key_v4_decrypt(pgp_skesk_packet *packet, void *password, size_t password_size, void *session_key,
														size_t session_key_size)
{
	byte_t key[32] = {0};
	byte_t buffer[48] = {0};
	byte_t zero_iv[16] = {0};

	byte_t iv_size = pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id);

	if (packet->session_key_size == 0)
	{
		return pgp_s2k_hash(&packet->s2k, password, password_size, session_key, session_key_size);
	}
	else
	{
		if ((packet->session_key_size + 1) > session_key_size)
		{
			return 0;
		}

		pgp_s2k_hash(&packet->s2k, password, password_size, session_key, session_key_size);

		// Decrypt the session key
		pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, key, session_key_size, zero_iv, iv_size, packet->session_key,
						session_key_size + 1, buffer, session_key_size + 1);

		memcpy(session_key, PTR_OFFSET(buffer, 1), session_key_size);
	}

	return 0;
}

static pgp_skesk_packet *pgp_skesk_packet_session_key_v5_v6_encrypt(pgp_skesk_packet *packet, void *password, size_t password_size,
																	void *session_key, size_t session_key_size, void *iv, size_t iv_size)
{
	byte_t ik[32] = {0};
	byte_t sk[32] = {0};
	byte_t info[4] = {0};

	byte_t *key = NULL;
	size_t result = 0;

	if (iv_size != pgp_aead_iv_size(packet->aead_algorithm_id))
	{
		return NULL;
	}

	info[0] = packet->header.tag;
	info[1] = packet->version;
	info[2] = packet->symmetric_key_algorithm_id;
	info[3] = packet->aead_algorithm_id;

	packet->iv_size = iv_size;
	packet->session_key_size = session_key_size;

	memcpy(packet->iv, iv, iv_size);

	pgp_s2k_hash(&packet->s2k, password, password_size, ik, packet->session_key_size);

	if (packet->version == PGP_SKESK_V6)
	{
		pgp_hkdf(PGP_SHA2_256, ik, 16, NULL, 0, info, 4, sk, packet->session_key_size);
		key = sk;
	}
	else // packet->version == PGP_SKESK_V5
	{
		key = ik;
	}

	result = pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, key, packet->session_key_size, packet->iv,
							  packet->iv_size, info, 4, session_key, session_key_size, packet->session_key, packet->session_key_size,
							  packet->tag, packet->tag_size);

	if (result == 0)
	{
		return NULL;
	}

	// Fill up the header now, we have enough information.
	pgp_skesk_packet_encode_header(packet);

	return packet;
}

static uint32_t pgp_skesk_packet_session_key_v5_v6_decrypt(pgp_skesk_packet *packet, void *password, size_t password_size,
														   void *session_key, size_t session_key_size)
{
	byte_t ik[32] = {0};
	byte_t sk[32] = {0};
	byte_t temp[32] = {0};
	byte_t tag[PGP_AEAD_TAG_SIZE] = {0};
	byte_t info[4] = {0};

	byte_t *key = NULL;
	size_t result = 0;

	info[0] = packet->header.tag;
	info[1] = packet->version;
	info[2] = packet->symmetric_key_algorithm_id;
	info[3] = packet->aead_algorithm_id;

	pgp_s2k_hash(&packet->s2k, password, password_size, ik, session_key_size);

	if (packet->version == PGP_SKESK_V6)
	{
		pgp_hkdf(PGP_SHA2_256, ik, 16, NULL, 0, info, 4, sk, packet->session_key_size);
		key = sk;
	}
	else // packet->version == PGP_SKESK_V5
	{
		key = ik;
	}

	result =
		pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, key, session_key_size, packet->iv, packet->iv_size,
						 info, 4, packet->session_key, session_key_size, temp, session_key_size, tag, PGP_AEAD_TAG_SIZE);

	if (result == 0)
	{
		return 0;
	}

	// Check tag
	if (memcmp(tag, packet->tag, PGP_AEAD_TAG_SIZE) != 0)
	{
		return 0;
	}

	// Copy the session key to the output
	memcpy(session_key, temp, session_key_size);

	return session_key_size;
}

pgp_skesk_packet *pgp_skesk_packet_new(byte_t version, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id, pgp_s2k *s2k)
{
	pgp_skesk_packet *packet = NULL;

	if (version != PGP_SKESK_V4 && version != PGP_SKESK_V5 && version != PGP_SKESK_V6)
	{
		return NULL;
	}

	if (pgp_symmetric_cipher_algorithm_validate(symmetric_key_algorithm_id) == 0)
	{
		return NULL;
	}

	if (version == PGP_SKESK_V6 || version == PGP_SKESK_V5)
	{
		// Unsupported ciphers for AEAD.
		if (symmetric_key_algorithm_id == PGP_PLAINTEXT || symmetric_key_algorithm_id == PGP_BLOWFISH ||
			symmetric_key_algorithm_id == PGP_TDES || symmetric_key_algorithm_id == PGP_IDEA)
		{
			return NULL;
		}

		if (pgp_aead_algorithm_validate(aead_algorithm_id) == 0)
		{
			return NULL;
		}
	}

	packet = malloc(sizeof(pgp_skesk_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_skesk_packet));

	packet->version = version;
	packet->symmetric_key_algorithm_id = symmetric_key_algorithm_id;

	if (version == PGP_SKESK_V6 || version == PGP_SKESK_V5)
	{
		packet->aead_algorithm_id = aead_algorithm_id;
		packet->tag_size = PGP_AEAD_TAG_SIZE;
	}
	else
	{
		packet->aead_algorithm_id = 0;
		packet->iv_size = 0;
		packet->tag_size = 0;
	}

	memcpy(&packet->s2k, s2k, sizeof(pgp_s2k));
	pgp_skesk_packet_encode_header(packet);

	return packet;
}

void pgp_skesk_packet_delete(pgp_skesk_packet *packet)
{
	free(packet);
}

pgp_skesk_packet *pgp_skesk_packet_session_key_encrypt(pgp_skesk_packet *packet, void *password, size_t password_size, void *session_key,
													   size_t session_key_size, void *iv, size_t iv_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	switch (packet->version)
	{
	case PGP_SKESK_V6:
	case PGP_SKESK_V5:
	{
		if (key_size != session_key_size)
		{
			return NULL;
		}

		return pgp_skesk_packet_session_key_v5_v6_encrypt(packet, password, password_size, session_key, session_key_size, iv, iv_size);
	}
	case PGP_SKESK_V4:
		return pgp_skesk_packet_session_key_v4_encrypt(packet, password, password_size, session_key, session_key_size);
	default:
		return NULL;
	}

	return NULL;
}

uint32_t pgp_skesk_packet_session_key_decrypt(pgp_skesk_packet *packet, void *password, size_t password_size, void *session_key,
											  size_t session_key_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	if (session_key_size < key_size)
	{
		return 0;
	}

	switch (packet->version)
	{
	case PGP_SKESK_V6:
	case PGP_SKESK_V5:
		return pgp_skesk_packet_session_key_v5_v6_decrypt(packet, password, password_size, session_key, key_size);
	case PGP_SKESK_V4:
		return pgp_skesk_packet_session_key_v4_decrypt(packet, password, password_size, session_key, key_size);
	default:
		return 0;
	}

	return 0;
}

pgp_skesk_packet *pgp_skesk_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_skesk_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_SKESK)
	{
		return NULL;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_skesk_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_skesk_packet));

	// Copy the header
	packet->header = header;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	if (packet->version == PGP_SKESK_V6 || packet->version == PGP_SKESK_V5)
	{
		void *result;
		byte_t count = 0;
		byte_t s2k_size = 0;

		// A 1-octet count of below 5 fields
		LOAD_8(&count, in + pos);
		pos += 1;

		// 1 octet symmetric key algorithm
		LOAD_8(&packet->symmetric_key_algorithm_id, in + pos);
		pos += 1;

		// 1 octet AEAD algorithm
		LOAD_8(&packet->aead_algorithm_id, in + pos);
		pos += 1;

		// 1 octet S2K size
		LOAD_8(&s2k_size, in + pos);
		pos += 1;

		// S2K specifier
		result = pgp_s2k_read(&packet->s2k, in + pos, packet->header.body_size - (pos - packet->header.header_size));

		if (result == NULL)
		{
			return NULL;
		}

		pos += s2k_size;

		// IV
		packet->iv_size = PGP_AEAD_TAG_SIZE;
		memcpy(packet->iv, in + pos, packet->iv_size);
		pos += packet->iv_size;

		// Encrypted session key.
		packet->session_key_size = packet->header.body_size - pos - 16;
		memcpy(packet->session_key, in + pos, packet->session_key_size);
		pos += packet->session_key_size;

		// Authetication key tag.
		packet->tag_size = 16;
		memcpy(packet->tag, in + pos, packet->tag_size);
		pos += packet->tag_size;
	}
	else if (packet->version == PGP_SKESK_V4)
	{
		void *result;

		// 1 octet symmetric key algorithm
		LOAD_8(&packet->symmetric_key_algorithm_id, in + pos);
		pos += 1;

		// S2K specifier
		result = pgp_s2k_read(&packet->s2k, in + pos, packet->header.body_size - (pos - packet->header.header_size));

		if (result == NULL)
		{
			return NULL;
		}

		pos += pgp_s2k_octets(&packet->s2k);

		// (Optional) Session key
		packet->session_key_size = packet->header.body_size - (pos - packet->header.header_size);

		if (packet->session_key_size > 0)
		{
			memcpy(packet->session_key, in + pos, packet->session_key_size);
			pos += packet->session_key_size;
		}
	}
	else
	{
		// Unknown version.
		return NULL;
	}

	return packet;
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
