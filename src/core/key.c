/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <key.h>
#include <s2k.h>

#include <md5.h>
#include <sha.h>

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
		pgp_rsa_key *key = packet->key_data;

		pos += mpi_read(key->n, in + pos, size - pos);
		pos += mpi_read(key->e, in + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = packet->key_data;

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		return pos;
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key_data;

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->q, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = packet->key_data;

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
		pgp_ecdsa_key *key = packet->key_data;

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
		pgp_x25519_key *key = packet->key_data;

		// 32 octets
		memcpy(key->public_key, in, 32);
		return 32;
	}
	case PGP_X448:
	{
		pgp_x448_key *key = packet->key_data;

		// 56 octets
		memcpy(key->public_key, in, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = packet->key_data;

		// 32 octets
		memcpy(key->public_key, in, 32);
		return 32;
	}
	case PGP_ED448:
	{
		pgp_ed448_key *key = packet->key_data;

		// 57 octets
		memcpy(key->public_key, in, 57);
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
		pgp_rsa_key *key = packet->key_data;

		pos += mpi_write(key->n, out + pos, size - pos);
		pos += mpi_write(key->e, out + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = packet->key_data;

		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->g, out + pos, size - pos);
		pos += mpi_write(key->y, out + pos, size - pos);

		return pos;
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key_data;

		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->q, out + pos, size - pos);
		pos += mpi_write(key->g, out + pos, size - pos);
		pos += mpi_write(key->y, out + pos, size - pos);

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = packet->key_data;

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
		pgp_ecdsa_key *key = packet->key_data;

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
		pgp_x25519_key *key = packet->key_data;

		// 32 octets
		memcpy(out, key->public_key, 32);
		return 32;
	}
	case PGP_X448:
	{
		pgp_x448_key *key = packet->key_data;

		// 56 octets
		memcpy(out, key->public_key, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = packet->key_data;

		// 32 octets
		memcpy(out, key->public_key, 32);
		return 32;
	}
	case PGP_ED448:
	{
		pgp_ed448_key *key = packet->key_data;

		// 57 octets
		memcpy(out, key->public_key, 57);
		return 57;
	}
	default:
		return 0;
	}
}

static uint32_t pgp_private_key_material_read(pgp_public_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *in = ptr;
	uint32_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = packet->key_data;

		pos += mpi_read(key->d, in + pos, size - pos);
		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->q, in + pos, size - pos);
		pos += mpi_read(key->u, in + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = packet->key_data;

		pos += mpi_read(key->x, in, size);
		return pos;
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key_data;

		pos += mpi_read(key->x, in, size);
		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = packet->key_data;

		pos += mpi_read(key->x, in, size);
		return pos;
	}
	case PGP_ECDSA:
	{
		pgp_ecdsa_key *key = packet->key_data;

		pos += mpi_read(key->x, in, size);
		return pos;
	}
	case PGP_X25519:
	{
		pgp_x25519_key *key = packet->key_data;

		// 32 octets
		memcpy(key->private_key, in, 32);
		return 32;
	}
	case PGP_X448:
	{
		pgp_x448_key *key = packet->key_data;

		// 56 octets
		memcpy(key->private_key, in, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = packet->key_data;

		// 32 octets
		memcpy(key->private_key, in, 32);
		return 32;
	}
	case PGP_ED448:
	{
		pgp_ed448_key *key = packet->key_data;

		// 57 octets
		memcpy(key->private_key, in, 57);
		return 57;
	}
	default:
		return 0;
	}
}

static uint32_t pgp_private_key_material_write(pgp_public_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = packet->key_data;

		pos += mpi_write(key->d, out + pos, size - pos);
		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->q, out + pos, size - pos);
		pos += mpi_write(key->u, out + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = packet->key_data;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key_data;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = packet->key_data;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_ECDSA:
	{
		pgp_ecdsa_key *key = packet->key_data;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_X25519:
	{
		pgp_x25519_key *key = packet->key_data;

		// 32 octets
		memcpy(out, key->private_key, 32);
		return 32;
	}
	case PGP_X448:
	{
		pgp_x448_key *key = packet->key_data;

		// 56 octets
		memcpy(out, key->private_key, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = packet->key_data;

		// 32 octets
		memcpy(out, key->private_key, 32);
		return 32;
	}
	case PGP_ED448:
	{
		pgp_ed448_key *key = packet->key_data;

		// 57 octets
		memcpy(out, key->private_key, 57);
		return 57;
	}
	default:
		return 0;
	}
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
		pos += pgp_private_key_material_read(packet, in + pos, packet->header.body_size - pos);

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
		pos += pgp_private_key_material_write(packet, out + pos, size - pos);

		if (packet->version != PGP_KEY_V6)
		{
			// 2-octet checksum
			LOAD_16(out + pos, packet->key_checksum);
			pos += 2;
		}
	}

	return pos;
}

static uint32_t pgp_key_fingerprint_v3(pgp_public_key_algorithms algorithm, void *key, byte_t figerprint_v3[MD5_HASH_SIZE])
{
	// MD5 of mpi without length octets
	md5_ctx md5;
	md5_init(&md5, sizeof(md5_ctx));

	// Support only these types for v3 keys
	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *pkey = key;
		uint32_t bytes = 0;

		// n
		bytes = CEIL_DIV(pkey->n->bits, 8);
		md5_update(&md5, pkey->n->bytes, bytes);

		// e
		bytes = CEIL_DIV(pkey->e->bits, 8);
		md5_update(&md5, pkey->e->bytes, bytes);

		md5_final(&md5, figerprint_v3);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *pkey = key;
		uint32_t bytes = 0;

		// p
		bytes = CEIL_DIV(pkey->p->bits, 8);
		md5_update(&md5, pkey->p->bytes, bytes);

		// g
		bytes = CEIL_DIV(pkey->g->bits, 8);
		md5_update(&md5, pkey->g->bytes, bytes);

		// y
		bytes = CEIL_DIV(pkey->y->bits, 8);
		md5_update(&md5, pkey->y->bytes, bytes);

		md5_final(&md5, figerprint_v3);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *pkey = key;
		uint32_t bytes = 0;

		// p
		bytes = CEIL_DIV(pkey->p->bits, 8);
		md5_update(&md5, pkey->p->bytes, bytes);

		// q
		bytes = CEIL_DIV(pkey->q->bits, 8);
		md5_update(&md5, pkey->q->bytes, bytes);

		// g
		bytes = CEIL_DIV(pkey->g->bits, 8);
		md5_update(&md5, pkey->g->bytes, bytes);

		// y
		bytes = CEIL_DIV(pkey->y->bits, 8);
		md5_update(&md5, pkey->y->bytes, bytes);

		md5_final(&md5, figerprint_v3);
	}
	break;
	default:
		return 0;
	}

	return MD5_HASH_SIZE;
}

static uint32_t pgp_key_fingerprint_v4(pgp_public_key_algorithms algorithm, uint32_t creation_time, uint16_t octet_count, void *key,
									   byte_t figerprint_v4[SHA1_HASH_SIZE])
{
	sha1_ctx sha1;
	sha1_init(&sha1, sizeof(md5_ctx));

	byte_t constant = 0x99;
	byte_t version = 4;
	uint16_t octet_count_be = BSWAP_16(octet_count);
	uint32_t creation_time_be = BSWAP_32(creation_time);

	sha1_update(&sha1, &constant, 1);
	sha1_update(&sha1, &octet_count_be, 2);
	sha1_update(&sha1, &version, 1);
	sha1_update(&sha1, &creation_time_be, 4);
	sha1_update(&sha1, &algorithm, 1);

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// n
		bits_be = BSWAP_16(pkey->n->bits);
		bytes = CEIL_DIV(pkey->n->bits, 8);
		sha1_update(&sha1, &bits_be, 2);
		sha1_update(&sha1, pkey->n->bytes, bytes);

		// e
		bits_be = BSWAP_16(pkey->e->bits);
		bytes = CEIL_DIV(pkey->e->bits, 8);
		sha1_update(&sha1, &bits_be, 2);
		sha1_update(&sha1, pkey->e->bytes, bytes);

		sha1_final(&sha1, figerprint_v4);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		sha1_update(&sha1, &bits_be, 2);
		sha1_update(&sha1, pkey->p->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		sha1_update(&sha1, &bits_be, 2);
		sha1_update(&sha1, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		sha1_update(&sha1, &bits_be, 2);
		sha1_update(&sha1, pkey->y->bytes, bytes);

		sha1_final(&sha1, figerprint_v4);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		sha1_update(&sha1, &bits_be, 2);
		sha1_update(&sha1, pkey->p->bytes, bytes);

		// q
		bits_be = BSWAP_16(pkey->q->bits);
		bytes = CEIL_DIV(pkey->q->bits, 8);
		sha1_update(&sha1, &bits_be, 2);
		sha1_update(&sha1, pkey->q->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		sha1_update(&sha1, &bits_be, 2);
		sha1_update(&sha1, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		sha1_update(&sha1, &bits_be, 2);
		sha1_update(&sha1, pkey->y->bytes, bytes);

		sha1_final(&sha1, figerprint_v4);
	}
	break;
	case PGP_ECDH:
	case PGP_ECDSA:
	case PGP_EDDSA_LEGACY:
		// TODO
		break;
	case PGP_X25519:
	{
		pgp_x25519_key *pkey = key;
		sha1_update(&sha1, pkey->public_key, 32);
		sha1_final(&sha1, figerprint_v4);
	}
	break;
	case PGP_X448:
	{
		pgp_x448_key *pkey = key;
		sha1_update(&sha1, pkey->public_key, 56);
		sha1_final(&sha1, figerprint_v4);
	}
	break;
	case PGP_ED25519:
	{

		pgp_ed25519_key *pkey = key;
		sha1_update(&sha1, pkey->public_key, 32);
		sha1_final(&sha1, figerprint_v4);
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_key *pkey = key;
		sha1_update(&sha1, pkey->public_key, 57);
		sha1_final(&sha1, figerprint_v4);
	}
	break;
	default:
		return 0;
	}

	return SHA1_HASH_SIZE;
}

static uint32_t pgp_key_fingerprint_v6(pgp_public_key_algorithms algorithm, uint32_t creation_time, uint32_t octet_count,
									   uint32_t material_count, void *key, byte_t figerprint_v6[SHA256_HASH_SIZE])
{
	sha256_ctx sha256;
	sha256_init(&sha256, sizeof(md5_ctx));

	byte_t constant = 0x9B;
	byte_t version = 4;
	uint32_t octet_count_be = BSWAP_32(octet_count);
	uint32_t material_count_be = BSWAP_32(octet_count);
	uint32_t creation_time_be = BSWAP_32(creation_time);

	sha256_update(&sha256, &constant, 1);
	sha256_update(&sha256, &octet_count_be, 4);
	sha256_update(&sha256, &version, 1);
	sha256_update(&sha256, &creation_time_be, 4);
	sha256_update(&sha256, &algorithm, 1);
	sha256_update(&sha256, &material_count_be, 4);

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// n
		bits_be = BSWAP_16(pkey->n->bits);
		bytes = CEIL_DIV(pkey->n->bits, 8);
		sha256_update(&sha256, &bits_be, 2);
		sha256_update(&sha256, pkey->n->bytes, bytes);

		// e
		bits_be = BSWAP_16(pkey->e->bits);
		bytes = CEIL_DIV(pkey->e->bits, 8);
		sha256_update(&sha256, &bits_be, 2);
		sha256_update(&sha256, pkey->e->bytes, bytes);

		sha256_final(&sha256, figerprint_v6);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		sha256_update(&sha256, &bits_be, 2);
		sha256_update(&sha256, pkey->p->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		sha256_update(&sha256, &bits_be, 2);
		sha256_update(&sha256, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		sha256_update(&sha256, &bits_be, 2);
		sha256_update(&sha256, pkey->y->bytes, bytes);

		sha256_final(&sha256, figerprint_v6);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		sha256_update(&sha256, &bits_be, 2);
		sha256_update(&sha256, pkey->p->bytes, bytes);

		// q
		bits_be = BSWAP_16(pkey->q->bits);
		bytes = CEIL_DIV(pkey->q->bits, 8);
		sha256_update(&sha256, &bits_be, 2);
		sha256_update(&sha256, pkey->q->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		sha256_update(&sha256, &bits_be, 2);
		sha256_update(&sha256, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		sha256_update(&sha256, &bits_be, 2);
		sha256_update(&sha256, pkey->y->bytes, bytes);

		sha256_final(&sha256, figerprint_v6);
	}
	break;
	case PGP_ECDH:
	case PGP_ECDSA:
	case PGP_EDDSA_LEGACY:
		// TODO
		break;
	case PGP_X25519:
	{
		pgp_x25519_key *pkey = key;
		sha256_update(&sha256, pkey->public_key, 32);
		sha256_final(&sha256, figerprint_v6);
	}
	break;
	case PGP_X448:
	{
		pgp_x448_key *pkey = key;
		sha256_update(&sha256, pkey->public_key, 56);
		sha256_final(&sha256, figerprint_v6);
	}
	break;
	case PGP_ED25519:
	{

		pgp_ed25519_key *pkey = key;
		sha256_update(&sha256, pkey->public_key, 32);
		sha256_final(&sha256, figerprint_v6);
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_key *pkey = key;
		sha1_update(&sha256, pkey->public_key, 57);
		sha256_final(&sha256, figerprint_v6);
	}
	break;
	default:
		return 0;
	}

	return SHA256_HASH_SIZE;
}

uint32_t pgp_key_fingerprint(void *key, void *fingerprint, uint32_t size);

uint32_t pgp_key_id(void *key, byte_t id[8])
{
	pgp_packet_header *header = key;
	byte_t tag = pgp_packet_get_type(header->tag);

	uint32_t status = 0;
	byte_t fingerprint[32] = {0};

	// For V3 RSA
	if (tag == PGP_PUBKEY || tag == PGP_PUBSUBKEY)
	{
		pgp_public_key_packet *packet = key;

		if (packet->version == PGP_KEY_V3)
		{
			if (packet->public_key_algorithm_id == PGP_RSA_ENCRYPT_OR_SIGN || packet->public_key_algorithm_id == PGP_RSA_ENCRYPT_ONLY ||
				packet->public_key_algorithm_id == PGP_RSA_SIGN_ONLY)
			{
				// Low 64 bits of public modulus
				pgp_rsa_key *rsa_key = packet->key_data;
				uint16_t bytes = CEIL_DIV(rsa_key->n->bits, 8);

				LOAD_64(id, &rsa_key->n->bytes[bytes - 8]);
			}
		}
	}
	else if (tag == PGP_SECKEY || tag == PGP_SECSUBKEY)
	{
		pgp_secret_key_packet *packet = key;

		if (packet->version == PGP_KEY_V3)
		{
			if (packet->public_key_algorithm_id == PGP_RSA_ENCRYPT_OR_SIGN || packet->public_key_algorithm_id == PGP_RSA_ENCRYPT_ONLY ||
				packet->public_key_algorithm_id == PGP_RSA_SIGN_ONLY)
			{
				// Low 64 bits of public modulus
				pgp_rsa_key *rsa_key = packet->public_key_data;
				uint16_t bytes = CEIL_DIV(rsa_key->n->bits, 8);

				LOAD_64(id, &rsa_key->n->bytes[bytes - 8]);
			}
		}
	}
	else
	{
		return 0;
	}

	// Last 64 bits of the fingerprint
	status = pgp_key_fingerprint(key, fingerprint, 32);

	if (status == 0)
	{
		return 0;
	}

	LOAD_64(id, PTR_OFFSET(fingerprint, status - 8));

	return 8;
}
