/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <key.h>

static uint32_t get_public_key_material_size(pgp_public_key_algorithms algorithm, uint32_t bits);

static uint32_t pgp_public_key_material_read(pgp_public_key_packet *packet, void *ptr);
static uint32_t pgp_public_key_material_write(pgp_public_key_packet *packet, void *ptr);

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
		// 4-octet scalar octet count for the public key material
		uint32_t key_data_size_be;

		LOAD_32(&key_data_size_be, in + pos);
		packet->key_data_size = BSWAP_32(key_data_size_be);
		pos += 4;
	}

	pos += pgp_public_key_material_read(packet, in + pos);

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
	// (For V6) A 4-octet scalar octet count for the public key material
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
		// 4-octet scalar octet count for the public key material
		uint32_t key_data_size = BSWAP_32(packet->key_data_size);

		LOAD_32(out + pos, &key_data_size);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, out + pos);

	return pos;
}

pgp_secret_key_packet *pgp_secret_key_packet_read(pgp_secret_key_packet *packet, void *data, size_t size);
size_t pgp_secret_key_packet_write(pgp_secret_key_packet *packet, void *ptr, size_t size);