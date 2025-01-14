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
#include <crypto.h>

#include <md5.h>
#include <sha.h>
#include <hash.h>

#include <stdlib.h>
#include <string.h>

static uint32_t get_public_key_material_octets(pgp_public_key_algorithms public_key_algorithm_id, void *key_data)
{
	switch (public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_public_rsa_key *key = key_data;

		return mpi_octets(key->n) + mpi_octets(key->e);
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_public_elgamal_key *key = key_data;

		return mpi_octets(key->p) + mpi_octets(key->g) + mpi_octets(key->y);
	}
	case PGP_DSA:
	{
		pgp_public_dsa_key *key = key_data;

		return mpi_octets(key->p) + mpi_octets(key->q) + mpi_octets(key->g) + mpi_octets(key->y);
	}
	case PGP_ECDH:
	{
		pgp_public_ecdh_key *key = key_data;

		return 5 + key->oid_size + mpi_octets(key->point);
	}
	case PGP_ECDSA:
	{
		pgp_public_ecdsa_key *key = key_data;

		return 1 + key->oid_size + mpi_octets(key->point);
	}
	case PGP_X25519:
	{
		return 32;
	}
	case PGP_X448:
	{
		return 56;
	}
	case PGP_ED25519:
	{
		return 32;
	}
	case PGP_ED448:
	{
		return 57;
	}
	default:
		return 0;
	}
}

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
		pgp_public_rsa_key *key = packet->key_data;

		pos += mpi_read(key->n, in + pos, size - pos);
		pos += mpi_read(key->e, in + pos, size - pos);

		packet->key_data_size = sizeof(pgp_public_rsa_key) + mpi_size(key->n->bits) + mpi_size(key->e->bits);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_public_elgamal_key *key = packet->key_data;

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		packet->key_data_size = sizeof(pgp_public_elgamal_key) + mpi_size(key->p->bits) + mpi_size(key->g->bits) + mpi_size(key->y->bits);

		return pos;
	}
	case PGP_DSA:
	{
		pgp_public_dsa_key *key = packet->key_data;

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->q, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		packet->key_data_size =
			sizeof(pgp_public_dsa_key) + mpi_size(key->p->bits) + mpi_size(key->q->bits) + mpi_size(key->g->bits) + mpi_size(key->y->bits);

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_public_ecdh_key *key = packet->key_data;

		// 1-octet oid size
		LOAD_8(&key->oid_size, in + pos);
		pos += 1;

		// N octets of oid
		memcpy(key->oid, in + pos, key->oid_size);
		pos += key->oid_size;

		// EC point
		pos += mpi_read(key->point, in + pos, size - pos);

		// KDF
		LOAD_8(&key->kdf.size, in + pos);
		pos += 1;

		LOAD_8(&key->kdf.extensions, in + pos);
		pos += 1;

		LOAD_8(&key->kdf.hash_algorithm_id, in + pos);
		pos += 1;

		LOAD_8(&key->kdf.symmetric_key_algorithm_id, in + pos);
		pos += 1;

		packet->key_data_size = sizeof(pgp_public_ecdh_key) + mpi_size(key->point->bits);

		return pos;
	}
	case PGP_ECDSA:
	{
		pgp_public_ecdsa_key *key = packet->key_data;

		// 1-octet oid size
		LOAD_8(&key->oid_size, in + pos);
		pos += 1;

		// N octets of oid
		memcpy(key->oid, in + pos, key->oid_size);
		pos += key->oid_size;

		// EC point
		pos += mpi_read(key->point, in + pos, size - pos);

		packet->key_data_size = sizeof(pgp_public_ecdsa_key) + mpi_size(key->point->bits);

		return pos;
	}
	case PGP_X25519:
	{
		pgp_public_x25519_key *key = packet->key_data;

		// 32 octets
		memcpy(key->public_key, in, 32);
		packet->key_data_size = 32;

		return 32;
	}
	case PGP_X448:
	{
		pgp_public_x448_key *key = packet->key_data;

		// 56 octets
		memcpy(key->public_key, in, 56);
		packet->key_data_size = 56;

		return 56;
	}
	case PGP_ED25519:
	{
		pgp_public_ed25519_key *key = packet->key_data;

		// 32 octets
		memcpy(key->public_key, in, 32);
		packet->key_data_size = 32;

		return 32;
	}
	case PGP_ED448:
	{
		pgp_public_ed448_key *key = packet->key_data;

		// 57 octets
		memcpy(key->public_key, in, 57);
		packet->key_data_size = 57;

		return 57;
	}
	default:
		// Copy unknown stuff directly
		memcpy(packet->key_data, ptr, size);
		return size;
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
		pgp_public_rsa_key *key = packet->key_data;

		pos += mpi_write(key->n, out + pos, size - pos);
		pos += mpi_write(key->e, out + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_public_elgamal_key *key = packet->key_data;

		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->g, out + pos, size - pos);
		pos += mpi_write(key->y, out + pos, size - pos);

		return pos;
	}
	case PGP_DSA:
	{
		pgp_public_dsa_key *key = packet->key_data;

		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->q, out + pos, size - pos);
		pos += mpi_write(key->g, out + pos, size - pos);
		pos += mpi_write(key->y, out + pos, size - pos);

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_public_ecdh_key *key = packet->key_data;

		// 1-octet oid size
		LOAD_8(out + pos, &key->oid_size);
		pos += 1;

		// N octets of oid
		memcpy(out + pos, key->oid, key->oid_size);
		pos += key->oid_size;

		// EC point
		pos += mpi_write(key->point, out + pos, size - pos);

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
		pgp_public_ecdsa_key *key = packet->key_data;

		// 1-octet oid size
		LOAD_8(out + pos, &key->oid_size);
		pos += 1;

		// N octets of oid
		memcpy(out + pos, key->oid, key->oid_size);
		pos += key->oid_size;

		// EC point
		pos += mpi_write(key->point, out + pos, size - pos);

		return pos;
	}
	case PGP_X25519:
	{
		pgp_public_x25519_key *key = packet->key_data;

		// 32 octets
		memcpy(out, key->public_key, 32);
		return 32;
	}
	case PGP_X448:
	{
		pgp_public_x448_key *key = packet->key_data;

		// 56 octets
		memcpy(out, key->public_key, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		pgp_public_ed25519_key *key = packet->key_data;

		// 32 octets
		memcpy(out, key->public_key, 32);
		return 32;
	}
	case PGP_ED448:
	{
		pgp_public_ed448_key *key = packet->key_data;

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
		pgp_private_rsa_key *key = packet->key_data;

		pos += mpi_read(key->d, in + pos, size - pos);
		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->q, in + pos, size - pos);
		pos += mpi_read(key->u, in + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_private_elgamal_key *key = packet->key_data;

		pos += mpi_read(key->x, in, size);
		return pos;
	}
	case PGP_DSA:
	{
		pgp_private_dsa_key *key = packet->key_data;

		pos += mpi_read(key->x, in, size);
		return pos;
	}
	case PGP_ECDH:
	{
		pgp_private_ecdh_key *key = packet->key_data;

		pos += mpi_read(key->x, in, size);
		return pos;
	}
	case PGP_ECDSA:
	{
		pgp_private_ecdsa_key *key = packet->key_data;

		pos += mpi_read(key->x, in, size);
		return pos;
	}
	case PGP_X25519:
	{
		pgp_private_x25519_key *key = packet->key_data;

		// 32 octets
		memcpy(key->private_key, in, 32);
		return 32;
	}
	case PGP_X448:
	{
		pgp_private_x448_key *key = packet->key_data;

		// 56 octets
		memcpy(key->private_key, in, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		pgp_private_ed25519_key *key = packet->key_data;

		// 32 octets
		memcpy(key->private_key, in, 32);
		return 32;
	}
	case PGP_ED448:
	{
		pgp_private_ed448_key *key = packet->key_data;

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
		pgp_private_rsa_key *key = packet->key_data;

		pos += mpi_write(key->d, out + pos, size - pos);
		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->q, out + pos, size - pos);
		pos += mpi_write(key->u, out + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_private_elgamal_key *key = packet->key_data;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_DSA:
	{
		pgp_private_dsa_key *key = packet->key_data;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_ECDH:
	{
		pgp_private_ecdh_key *key = packet->key_data;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_ECDSA:
	{
		pgp_private_ecdsa_key *key = packet->key_data;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_X25519:
	{
		pgp_private_x25519_key *key = packet->key_data;

		// 32 octets
		memcpy(out, key->private_key, 32);
		return 32;
	}
	case PGP_X448:
	{
		pgp_private_x448_key *key = packet->key_data;

		// 56 octets
		memcpy(out, key->private_key, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		pgp_private_ed25519_key *key = packet->key_data;

		// 32 octets
		memcpy(out, key->private_key, 32);
		return 32;
	}
	case PGP_ED448:
	{
		pgp_private_ed448_key *key = packet->key_data;

		// 57 octets
		memcpy(out, key->private_key, 57);
		return 57;
	}
	default:
		return 0;
	}
}

pgp_public_key_packet *pgp_public_key_packet_new(pgp_packet_type type, pgp_key_version version, uint32_t key_creation_time,
												 uint16_t key_expiry_days, byte_t public_key_algorithm_id, void *key_data,
												 uint32_t key_data_size)
{
	pgp_public_key_packet *packet = NULL;
	pgp_packet_header_format format = PGP_HEADER;
	uint32_t body_size = 0;

	if (type != PGP_PUBKEY && type != PGP_PUBSUBKEY)
	{
		return NULL;
	}

	if (version != PGP_KEY_V6 && version != PGP_KEY_V4 && version != PGP_KEY_V3 && version != PGP_KEY_V2)
	{
		return NULL;
	}

	if (pgp_public_cipher_algorithm_validate(public_key_algorithm_id) == 0)
	{
		return 0;
	}

	if (version == PGP_KEY_V6)
	{
		body_size = 10;
	}
	else if (version == PGP_KEY_V4)
	{
		body_size = 6;
	}
	else // (version == PGP_KEY_V3 || version == PGP_KEY_V2)
	{
		body_size = 8;
		format = PGP_LEGACY_HEADER;
	}

	packet = malloc(sizeof(pgp_public_key_packet) + key_data_size);

	if (packet == NULL)
	{
		return 0;
	}

	memset(packet, 0, sizeof(pgp_public_key_packet) + key_data_size);

	packet->key_creation_time = key_creation_time;
	packet->key_expiry_days = key_expiry_days;
	packet->public_key_algorithm_id = public_key_algorithm_id;

	memcpy(packet->key_data, key_data, key_data_size);
	packet->key_data_size = key_data_size;
	packet->key_data_octets = get_public_key_material_octets(public_key_algorithm_id, key_data);

	body_size += packet->key_data_octets;

	packet->header = pgp_encode_packet_header(format, type, body_size);

	return packet;
}

void pgp_public_key_packet_delete(pgp_public_key_packet *packet)
{
	free(packet);
}

pgp_public_key_packet *pgp_public_key_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_public_key_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_PUBKEY && pgp_packet_get_type(header.tag) != PGP_PUBSUBKEY)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_public_key_packet) + header.body_size);

	if (packet == NULL)
	{
		return NULL;
	}

	packet->key_data = PTR_OFFSET(packet, sizeof(pgp_public_key_packet));

	// Copy the header
	packet->header = header;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

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
		uint32_t key_data_octets_be;

		LOAD_32(&key_data_octets_be, in + pos);
		packet->key_data_octets = BSWAP_32(key_data_octets_be);
		pos += 4;
	}
	else
	{
		packet->key_data_octets = (header.body_size + header.header_size) - pos;
	}

	pos += pgp_public_key_material_read(packet, in + pos, packet->key_data_octets);

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

	required_size = 1 + 4 + 1 + packet->key_data_octets;
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
		uint32_t key_data_octets = BSWAP_32(packet->key_data_octets);

		LOAD_32(out + pos, &key_data_octets);
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
		uint32_t public_key_data_octets_be;

		LOAD_32(&public_key_data_octets_be, in + pos);
		packet->public_key_data_octets = BSWAP_32(public_key_data_octets_be);
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
		memcpy(packet->private_key_data, in + pos, packet->private_key_data_octets);
		pos += packet->private_key_data_octets;
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

	required_size = 1 + 4 + 1 + 1 + packet->public_key_data_octets + packet->private_key_data_octets;
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
		uint32_t public_key_data_octets_be = BSWAP_32(packet->public_key_data_octets);

		LOAD_32(out + pos, &public_key_data_octets_be);
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
		memcpy(out + pos, packet->private_key_data, packet->private_key_data_octets);
		pos += packet->private_key_data_octets;
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

static hash_ctx *pgp_hash_key_material(hash_ctx *hctx, pgp_public_key_algorithms algorithm, void *key)
{
	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_public_rsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// n
		bits_be = BSWAP_16(pkey->n->bits);
		bytes = CEIL_DIV(pkey->n->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->n->bytes, bytes);

		// e
		bits_be = BSWAP_16(pkey->e->bits);
		bytes = CEIL_DIV(pkey->e->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->e->bytes, bytes);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_public_elgamal_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->p->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->y->bytes, bytes);
	}
	break;
	case PGP_DSA:
	{
		pgp_public_dsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->p->bytes, bytes);

		// q
		bits_be = BSWAP_16(pkey->q->bits);
		bytes = CEIL_DIV(pkey->q->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->q->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->y->bytes, bytes);
	}
	break;
	case PGP_ECDH:
	{
		pgp_public_ecdh_key *pkey = key;

		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// OID
		hash_update(hctx, &pkey->oid_size, 1);
		hash_update(hctx, pkey->oid, pkey->oid_size);

		// EC point
		bits_be = BSWAP_16(pkey->point->bits);
		bytes = CEIL_DIV(pkey->point->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->point->bytes, bytes);

		// KDF
		hash_update(hctx, &pkey->kdf.size, 1);
		hash_update(hctx, &pkey->kdf.extensions, 1);
		hash_update(hctx, &pkey->kdf.hash_algorithm_id, 1);
		hash_update(hctx, &pkey->kdf.symmetric_key_algorithm_id, 1);
	}
	break;
	case PGP_ECDSA:
	case PGP_EDDSA_LEGACY:
	{
		pgp_public_ecdsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// OID
		hash_update(hctx, &pkey->oid_size, 1);
		hash_update(hctx, pkey->oid, pkey->oid_size);

		// EC point
		bits_be = BSWAP_16(pkey->point->bits);
		bytes = CEIL_DIV(pkey->point->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->point->bytes, bytes);
	}
	break;
	case PGP_X25519:
	{
		pgp_public_x25519_key *pkey = key;
		hash_update(hctx, pkey->public_key, 32);
	}
	break;
	case PGP_X448:
	{
		pgp_public_x448_key *pkey = key;
		hash_update(hctx, pkey->public_key, 56);
	}
	break;
	case PGP_ED25519:
	{

		pgp_public_ed25519_key *pkey = key;
		hash_update(hctx, pkey->public_key, 32);
	}
	break;
	case PGP_ED448:
	{
		pgp_public_ed448_key *pkey = key;
		hash_update(hctx, pkey->public_key, 57);
	}
	break;
	default:
		return 0;
	}
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
		pgp_public_rsa_key *pkey = key;
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
		pgp_public_elgamal_key *pkey = key;
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
		pgp_public_dsa_key *pkey = key;
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
	hash_ctx *hctx = NULL;
	byte_t buffer[512] = {0};

	byte_t constant = 0x99;
	byte_t version = 4;
	uint16_t octet_count_be = BSWAP_16(octet_count);
	uint32_t creation_time_be = BSWAP_32(creation_time);

	hash_init(buffer, 512, HASH_SHA1);

	hash_update(hctx, &constant, 1);
	hash_update(hctx, &octet_count_be, 2);
	hash_update(hctx, &version, 1);
	hash_update(hctx, &creation_time_be, 4);
	hash_update(hctx, &algorithm, 1);

	hctx = pgp_hash_key_material(hctx, algorithm, key);

	if (hctx == NULL)
	{
		return 0;
	}

	hash_final(hctx, figerprint_v4, SHA1_HASH_SIZE);

	return SHA1_HASH_SIZE;
}

static uint32_t pgp_key_fingerprint_v6(pgp_public_key_algorithms algorithm, uint32_t creation_time, uint32_t octet_count,
									   uint32_t material_count, void *key, byte_t figerprint_v6[SHA256_HASH_SIZE])
{
	hash_ctx *hctx = NULL;
	byte_t buffer[512] = {0};

	byte_t constant = 0x9B;
	byte_t version = 4;
	uint32_t octet_count_be = BSWAP_32(octet_count);
	uint32_t material_count_be = BSWAP_32(octet_count);
	uint32_t creation_time_be = BSWAP_32(creation_time);

	hash_init(buffer, 512, HASH_SHA256);

	hash_update(hctx, &constant, 1);
	hash_update(hctx, &octet_count_be, 4);
	hash_update(hctx, &version, 1);
	hash_update(hctx, &creation_time_be, 4);
	hash_update(hctx, &algorithm, 1);
	hash_update(hctx, &material_count_be, 4);

	hctx = pgp_hash_key_material(hctx, algorithm, key);

	if (hctx == NULL)
	{
		return 0;
	}

	hash_final(hctx, figerprint_v6, SHA256_HASH_SIZE);

	return SHA256_HASH_SIZE;
}

uint32_t pgp_key_fingerprint(void *key, void *fingerprint, uint32_t size)
{
	pgp_packet_header *header = key;
	byte_t tag = pgp_packet_get_type(header->tag);

	if (tag == PGP_PUBKEY || tag == PGP_PUBSUBKEY)
	{
		pgp_public_key_packet *packet = key;

		switch (packet->version)
		{
		case PGP_KEY_V2:
		case PGP_KEY_V3:
		{
			if (size < MD5_HASH_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v3(packet->public_key_algorithm_id, packet->key_data, fingerprint);
		}
		case PGP_KEY_V4:
		{
			if (size < SHA1_HASH_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v4(packet->public_key_algorithm_id, packet->key_creation_time, (uint16_t)packet->key_data_octets + 6,
										  packet->key_data, fingerprint);
		}
		case PGP_KEY_V6:
		{
			if (size < SHA256_HASH_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v6(packet->public_key_algorithm_id, packet->key_creation_time, packet->key_data_octets + 9,
										  packet->key_data_octets, packet->key_data, fingerprint);
		}
		default:
			return 0;
		}
	}
	else if (tag == PGP_SECKEY || tag == PGP_SECSUBKEY)
	{
		pgp_secret_key_packet *packet = key;

		switch (packet->version)
		{
		case PGP_KEY_V2:
		case PGP_KEY_V3:
		{
			if (size < MD5_HASH_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v3(packet->public_key_algorithm_id, packet->public_key_data, fingerprint);
		}
		case PGP_KEY_V4:
		{
			if (size < SHA1_HASH_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v4(packet->public_key_algorithm_id, packet->key_creation_time,
										  (uint16_t)packet->public_key_data_size + 6, packet->public_key_data, fingerprint);
		}
		case PGP_KEY_V6:
		{
			if (size < SHA256_HASH_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v6(packet->public_key_algorithm_id, packet->key_creation_time, packet->public_key_data_size + 9,
										  packet->public_key_data_size, packet->public_key_data, fingerprint);
		}
		default:
			return 0;
		}
	}
	else
	{
		return 0;
	}

	return 0;
}

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
				pgp_public_rsa_key *rsa_key = packet->key_data;
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
				pgp_public_rsa_key *rsa_key = packet->public_key_data;
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
