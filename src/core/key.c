/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <key.h>
#include <s2k.h>

#include <string.h>

static uint32_t get_public_key_material_size(pgp_public_key_algorithms algorithm, uint32_t bits);

static uint32_t pgp_public_key_material_read(pgp_public_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *in = ptr;
	uint32_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_public_key *key = packet->key_data;

		pos += mpi_read(key->n, in + pos, size - pos);
		pos += mpi_read(key->e, in + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_public_key *key = packet->key_data;

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		return pos;
	}
	case PGP_DSA:
	{
		pgp_dsa_public_key *key = packet->key_data;

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->q, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_public_key *key = packet->key_data;

		// 1-octet oid size
		LOAD_8(&key->oid_size, in + pos);
		pos += 1;

		// N octets of oid
		memcpy(key->oid, in + pos, key->oid_size);
		pos += key->oid_size;

		// EC point
		memcpy(key->point, in + pos, key->point_size);
		pos += key->point_size;

		// KDF
		LOAD_8(&key->kdf.size, in + pos);
		pos += 1;

		LOAD_8(&key->kdf.extensions, in + pos);
		pos += 1;

		LOAD_8(&key->kdf.hash_algorithm_id, in + pos);
		pos += 1;

		LOAD_8(&key->kdf.symmetric_key_algorithm_id, in + pos);
		pos += 1;

		return pos;
	}
	case PGP_ECDSA:
	{
		pgp_ecdsa_public_key *key = packet->key_data;

		// 1-octet oid size
		LOAD_8(&key->oid_size, in + pos);
		pos += 1;

		// N octets of oid
		memcpy(key->oid, in + pos, key->oid_size);
		pos += key->oid_size;

		// EC point
		memcpy(key->point, in + pos, key->point_size);
		pos += key->point_size;

		return pos;
	}
	case PGP_X25519:
	{
		// 32 octets
		memcpy(packet->key_data, in, 32);
		return 32;
	}
	case PGP_X448:
	{
		// 56 octets
		memcpy(packet->key_data, in, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		// 32 octets
		memcpy(packet->key_data, in, 32);
		return 32;
	}
	case PGP_ED448:
	{
		// 57 octets
		memcpy(packet->key_data, in, 57);
		return 57;
	}
	default:
		return 0;
	}
}

static uint32_t pgp_public_key_material_write(pgp_public_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_public_key *key = packet->key_data;

		pos += mpi_write(key->n, out + pos, size - pos);
		pos += mpi_write(key->e, out + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_public_key *key = packet->key_data;

		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->g, out + pos, size - pos);
		pos += mpi_write(key->y, out + pos, size - pos);

		return pos;
	}
	case PGP_DSA:
	{
		pgp_dsa_public_key *key = packet->key_data;

		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->q, out + pos, size - pos);
		pos += mpi_write(key->g, out + pos, size - pos);
		pos += mpi_write(key->y, out + pos, size - pos);

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_public_key *key = packet->key_data;

		// 1-octet oid size
		LOAD_8(out + pos, &key->oid_size);
		pos += 1;

		// N octets of oid
		memcpy(out + pos, key->oid, key->oid_size);
		pos += key->oid_size;

		// EC point
		memcpy(out + pos, key->point, key->point_size);
		pos += key->point_size;

		// KDF
		LOAD_8(out + pos, &key->kdf.size);
		pos += 1;

		LOAD_8(out + pos, &key->kdf.extensions);
		pos += 1;

		LOAD_8(out + pos, &key->kdf.hash_algorithm_id);
		pos += 1;

		LOAD_8(out + pos, &key->kdf.symmetric_key_algorithm_id);
		pos += 1;

		return pos;
	}
	case PGP_ECDSA:
	{
		pgp_ecdsa_public_key *key = packet->key_data;

		// 1-octet oid size
		LOAD_8(out + pos, &key->oid_size);
		pos += 1;

		// N octets of oid
		memcpy(out + pos, key->oid, key->oid_size);
		pos += key->oid_size;

		// EC point
		memcpy(out + pos, key->point, key->point_size);
		pos += key->point_size;

		return pos;
	}
	case PGP_X25519:
	{
		// 32 octets
		memcpy(out, packet->key_data, 32);
		return 32;
	}
	case PGP_X448:
	{
		// 56 octets
		memcpy(out, packet->key_data, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		// 32 octets
		memcpy(out, packet->key_data, 32);
		return 32;
	}
	case PGP_ED448:
	{
		// 57 octets
		memcpy(out, packet->key_data, 57);
		return 57;
	}
	default:
		return 0;
	}
}

static uint32_t pgp_private_key_material_read(pgp_public_key_packet *packet, void *ptr)
{
	return 0;
}

static uint32_t pgp_private_key_material_write(pgp_public_key_packet *packet, void *ptr)
{
	return 0;
}

pgp_public_key_packet *pgp_public_key_packet_read(pgp_public_key_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	if (packet->version != PGP_KEY_V2 && packet->version != PGP_KEY_V3 && packet->version != PGP_KEY_V4 && packet->version != PGP_KEY_V6)
	{
		return 0;
	}

	// 4-octet number denoting the time that the key was created.
	uint32_t key_creation_time_be;

	LOAD_32(&key_creation_time_be, in + pos);
	packet->key_creation_time = BSWAP_32(key_creation_time_be);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		uint16_t key_expiry_days_be;

		LOAD_16(&key_expiry_days_be, in + pos);
		packet->key_expiry_days = BSWAP_16(key_expiry_days_be);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(&packet->public_key_algorithm_id, in + pos);
	pos += 1;

	if (packet->version == PGP_KEY_V6)
	{
		// 4-octet scalar count for the public key material
		uint32_t key_data_size_be;

		LOAD_32(&key_data_size_be, in + pos);
		packet->key_data_size = BSWAP_32(key_data_size_be);
		pos += 4;
	}

	pos += pgp_public_key_material_read(packet, in + pos, packet->header.body_size - pos);

	return packet;
}

size_t pgp_public_key_packet_write(pgp_public_key_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number 3 or 4.
	// A 4-octet number denoting the time that the key was created.
	// (For V3) A 2-octet number denoting expiry in days.
	// A 1-octet public key algorithm.
	// (For V6) A 4-octet scalar count for the public key material
	// One or more MPIs comprising the key.

	required_size = 1 + 4 + 1 + packet->key_data_size;
	required_size += (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3) ? 2 : 0;
	required_size += (packet->version == PGP_KEY_V6) ? 4 : 0;
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

	// 4-octet number denoting the time that the key was created
	uint32_t key_creation_time = BSWAP_32(packet->key_creation_time);

	LOAD_32(out + pos, &key_creation_time);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		uint16_t key_expiry_days = BSWAP_16(packet->key_expiry_days);

		LOAD_16(out + pos, &key_expiry_days);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	if (packet->version == PGP_KEY_V6)
	{
		// 4-octet scalar count for the public key material
		uint32_t key_data_size = BSWAP_32(packet->key_data_size);

		LOAD_32(out + pos, &key_data_size);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, out + pos, size - pos);

	return pos;
}

pgp_secret_key_packet *pgp_secret_key_packet_read(pgp_secret_key_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	if (packet->version != PGP_KEY_V2 && packet->version != PGP_KEY_V3 && packet->version != PGP_KEY_V4 && packet->version != PGP_KEY_V6)
	{
		return 0;
	}

	// 4-octet number denoting the time that the key was created.
	uint32_t key_creation_time_be;

	LOAD_32(&key_creation_time_be, in + pos);
	packet->key_creation_time = BSWAP_32(key_creation_time_be);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		uint16_t key_expiry_days_be;

		LOAD_16(&key_expiry_days_be, in + pos);
		packet->key_expiry_days = BSWAP_16(key_expiry_days_be);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(&packet->public_key_algorithm_id, in + pos);
	pos += 1;

	if (packet->version == PGP_KEY_V6)
	{
		// 4-octet scalar count for the public key material
		uint32_t public_key_data_size_be;

		LOAD_32(&public_key_data_size_be, in + pos);
		packet->public_key_data_size = BSWAP_32(public_key_data_size_be);
		pos += 4;
	}

	pos += pgp_public_key_material_read(packet, in + pos, packet->header.body_size - pos);

	// 1 octet of S2K usage
	LOAD_8(&packet->s2k_usage, in + pos);
	pos += 1;

	if (packet->s2k_usage != 0)
	{
		void *result;

		byte_t s2k_size = 0;
		byte_t conditional_field_size = 0;

		if (packet->version == PGP_KEY_V6)
		{
			// 1-octet scalar count of S2K fields
			LOAD_8(&conditional_field_size, in + pos);
			pos += 1;
		}

		// 1 octet symmetric key algorithm
		LOAD_8(&packet->symmetric_key_algorithm_id, in + pos);
		pos += 1;

		if (packet->s2k_usage == 253)
		{
			// 1 octet AEAD algorithm
			LOAD_8(&packet->aead_algorithm_id, in + pos);
			pos += 1;
		}

		if (packet->version == PGP_KEY_V6)
		{
			// 1-octet count of S2K specifier
			LOAD_8(&s2k_size, in + pos);
			pos += 1;
		}

		// S2K specifier
		result = pgp_s2k_read(&packet->s2k_algorithm, in + pos, s2k_size != 0 ? s2k_size : (packet->header.body_size - pos));

		if (result == NULL)
		{
			return NULL;
		}

		pos += pgp_s2k_size(&packet->s2k_algorithm);

		// IV
		memcpy(packet->iv, in + pos, 16);
		pos += 16;

		// Encrypted private key
		memcpy(packet->private_key_data, in + pos, packet->private_key_data_size);
		pos += packet->private_key_data_size;
	}
	else
	{
		// Plaintext private key
		pos += pgp_private_key_material_read(packet, in + pos);

		if (packet->version != PGP_KEY_V6)
		{
			// 2-octet checksum
			LOAD_16(packet->key_checksum, in + pos);
			pos += 2;
		}
	}

	return packet;
}

size_t pgp_secret_key_packet_write(pgp_secret_key_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	byte_t s2k_size = 0;
	byte_t conditional_field_size = 0;

	// A 1-octet version number 3 or 4.
	// A 4-octet number denoting the time that the key was created.
	// (For V3) A 2-octet number denoting expiry in days.
	// A 1-octet public key algorithm.
	// (For V6) A 4-octet scalar count for the public key material
	// One or more MPIs comprising the public key.
	// A 1-octet of S2K usage
	// (For V6) A 1-octet scalar count of s2k fields if above field is non zero
	// (Plaintext or encrypted) Private key data.
	// (For V3 and V4) A 2-octet checksum of private key if not encrypted

	s2k_size = (packet->s2k_usage != 0) ? pgp_s2k_size(&packet->s2k_algorithm) : 0;

	required_size = 1 + 4 + 1 + 1 + packet->public_key_data_size + packet->private_key_data_size;
	required_size += (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3) ? 2 : 0;

	if (packet->s2k_usage == 0)
	{
		if (packet->version != PGP_KEY_V6)
		{
			required_size += 2;
		}
	}

	if (packet->version == PGP_KEY_V6)
	{
		required_size += 4;

		if (packet->s2k_usage != 0)
		{
			required_size += 1;
		}
	}

	required_size += packet->header.header_size;

	switch (packet->s2k_usage)
	{
	case 0: // Plaintext
		conditional_field_size = 0;
		break;
	case 253: // AEAD
		// A 1-octet symmetric key algorithm.
		// A 1-octet AEAD algorithm.
		// (For V6) A 1-octet count of S2K specifier
		// A S2K specifier
		// IV
		conditional_field_size = 1 + 1 + 16 + s2k_size;
		conditional_field_size += (packet->version == PGP_KEY_V6) ? 1 : 0;
		break;
	case 254: // CFB
	case 255: // Malleable CFB
		// A 1-octet symmetric key algorithm.
		// (For V6) A 1-octet count of S2K specifier
		// A S2K specifier
		// IV
		conditional_field_size = 1 + 16 + s2k_size;
		conditional_field_size += (packet->version == PGP_KEY_V6) ? 1 : 0;
	default:
		return 0;
	}

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 4-octet number denoting the time that the key was created
	uint32_t key_creation_time = BSWAP_32(packet->key_creation_time);

	LOAD_32(out + pos, &key_creation_time);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		uint16_t key_expiry_days = BSWAP_16(packet->key_expiry_days);

		LOAD_16(out + pos, &key_expiry_days);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	if (packet->version == PGP_KEY_V6)
	{
		// 4-octet scalar count for the public key material
		uint32_t public_key_data_size = BSWAP_32(packet->public_key_data_size);

		LOAD_32(out + pos, &public_key_data_size);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, out + pos, size - pos);

	// 1 octet of S2K usage
	LOAD_8(out + pos, &packet->s2k_usage);
	pos += 1;

	if (conditional_field_size != 0)
	{
		if (packet->version == PGP_KEY_V6)
		{
			// 1-octet scalar count of S2K fields
			LOAD_8(out + pos, &conditional_field_size);
			pos += 1;
		}

		// 1 octet symmetric key algorithm
		LOAD_8(out + pos, &packet->symmetric_key_algorithm_id);
		pos += 1;

		if (packet->s2k_usage == 253)
		{
			// 1 octet AEAD algorithm
			LOAD_8(out + pos, &packet->aead_algorithm_id);
			pos += 1;
		}

		if (packet->version == PGP_KEY_V6)
		{
			// 1-octet count of S2K specifier
			LOAD_8(out + pos, &s2k_size);
			pos += 1;
		}

		// S2K specifier
		pos += pgp_s2k_write(&packet->s2k_algorithm, out + pos);

		// IV
		memcpy(out + pos, packet->iv, 16);
		pos += 16;

		// Encrypted private key
		memcpy(out + pos, packet->private_key_data, packet->private_key_data_size);
		pos += packet->private_key_data_size;
	}
	else
	{
		// Plaintext private key
		pos += pgp_private_key_material_write(packet, out + pos);

		if (packet->version != PGP_KEY_V6)
		{
			// 2-octet checksum
			LOAD_16(out + pos, packet->key_checksum);
			pos += 2;
		}
	}

	return pos;
}
