/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <seipd.h>
#include <ciphers.h>

#include <stdlib.h>
#include <string.h>

#include <hkdf.h>

pgp_sed_packet *pgp_sed_packet_read(pgp_sed_packet *packet, void *data, size_t size)
{
	// Copy the packet data.
	memcpy(packet->data, (byte_t *)data + packet->header.header_size, packet->header.body_size);

	return packet;
}

size_t pgp_sed_packet_write(pgp_sed_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// N bytes of symmetrically encryrpted data

	required_size = packet->header.header_size + packet->header.body_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Data
	memcpy(out + pos, packet->data, packet->header.body_size);
	pos += packet->header.body_size;

	return pos;
}

static size_t pgp_seipd_packet_v1_write(pgp_seipd_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number with value 1.
	// N octets of symmetrically encryrpted data

	required_size = packet->header.header_size + 1 + packet->data_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// Data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	return pos;
}

static size_t pgp_seipd_packet_v2_write(pgp_seipd_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number with value 2.
	// A 1-octet symmetric key algorithm.
	// A 1-octet AEAD algorithm.
	// A 1-octet chunk size.
	// A 32-octets of salt.
	// Symmetrically encryrpted data
	// Authentication tag

	required_size = packet->header.header_size + 1 + 1 + 1 + 1 + 32 + packet->data_size + packet->tag_size;

	if (size < required_size)
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

	// 1 octet AEAD algorithm
	LOAD_8(out + pos, &packet->aead_algorithm_id);
	pos += 1;

	// 1 octet chunk size
	LOAD_8(out + pos, &packet->chunk_size);
	pos += 1;

	// 32-octets of salt
	memcpy(out + pos, packet->salt, 32);
	pos += 32;

	// Data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	// Tag
	memcpy(out + pos, packet->tag, packet->tag_size);
	pos += packet->tag_size;

	return pos;
}

pgp_seipd_packet *pgp_seipd_packet_new(pgp_packet_header_type format, byte_t version, byte_t symmetric_key_algorithm_id,
									   byte_t aead_algorithm_id, byte_t chunk_size)
{
	pgp_seipd_packet *packet = NULL;

	if (version != PGP_SEIPD_V2 && version != PGP_SEIPD_V1)
	{
		return NULL;
	}

	if (version == PGP_SEIPD_V2)
	{
		if (chunk_size > 16)
		{
			return NULL;
		}
	}

	packet = malloc(sizeof(pgp_seipd_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	if (version == PGP_SEIPD_V2)
	{
		packet->version = PGP_SEIPD_V2;
		packet->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
		packet->aead_algorithm_id = aead_algorithm_id;
		packet->chunk_size = chunk_size;
	}
	else
	{
		// Only set the version.
		packet->version = PGP_SEIPD_V1;
	}

	return packet;
}

void pgp_seipd_packet_delete(pgp_seipd_packet *packet)
{
	free(packet->data);
	free(packet);
}

pgp_seipd_packet *pgp_seipd_packet_encrypt(pgp_seipd_packet *packet, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id,
										   byte_t salt[32], void *session_key, size_t session_key_size, void *data, size_t data_size)
{
	byte_t *in = data;
	byte_t *out = NULL;

	if (packet->version == PGP_SEIPD_V2)
	{
		uint32_t chunk_size = 1u << (packet->chunk_size + 6);
		byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
		byte_t iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);

		size_t in_pos = 0;
		size_t out_pos = 0;
		size_t count = 0;

		byte_t derived_key[48] = {0};
		byte_t info[5] = {0};

		info[0] = packet->header.tag;
		info[1] = packet->version;
		info[2] = packet->symmetric_key_algorithm_id;
		info[3] = packet->aead_algorithm_id;
		info[4] = packet->chunk_size;

		// Copy the salt
		memcpy(packet->salt, salt, 32);

		// Derive the message key
		hkdf(HASH_SHA256, session_key, session_key_size, salt, 32, info, 5, derived_key, key_size + iv_size - 8);

		// Encrypt the data paritioned by chunk size
		packet->data_size = data_size + (CEIL_DIV(data_size, chunk_size) * PGP_AEAD_TAG_SIZE);
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			return NULL;
		}

		out = packet->data;

		while (in_pos < data_size)
		{
			byte_t tag[PGP_AEAD_TAG_SIZE] = {0};
			uint32_t in_size = MIN(chunk_size, data_size - in_pos);

			// Encrypt the data
			pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size,
							 PTR_OFFSET(derived_key, key_size), (iv_size - 8), info, 5, in + in_pos, in_size, out + out_pos, in_size, tag,
							 PGP_AEAD_TAG_SIZE);

			// Copy the tag to the end
			memcpy(out + in_size, tag, PGP_AEAD_TAG_SIZE);

			in_pos += in_size;
			out_pos += in_size + PGP_AEAD_TAG_SIZE;
			++count;
		}

		// Final authentication tag
		byte_t aad[16] = {0};
		byte_t *pc = (byte_t *)count;

		packet->tag_size = PGP_AEAD_TAG_SIZE;

		// Same as info
		aad[0] = info[0];
		aad[1] = info[1];
		aad[2] = info[2];
		aad[3] = info[3];
		aad[4] = info[4];

		// Store number of chunks as 8 byte big endian
		aad[5] = pc[7];
		aad[6] = pc[6];
		aad[7] = pc[5];
		aad[8] = pc[4];
		aad[9] = pc[3];
		aad[10] = pc[2];
		aad[11] = pc[1];
		aad[12] = pc[0];

		pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size,
						 PTR_OFFSET(derived_key, key_size), (iv_size - 8), aad, 13, NULL, 0, NULL, 0, packet->tag, PGP_AEAD_TAG_SIZE);

		packet->header = encode_packet_header(PGP_HEADER, PGP_SEIPD, 4 + 32 + packet->tag_size + packet->data_size);
	}
	else
	{
		// TODO
	}

	return packet;
}

size_t pgp_seipd_packet_decrypt(pgp_seipd_packet *packet, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id, void *session_key,
								size_t session_key_size, void *data, size_t data_size)
{
	byte_t *in = packet->data;
	byte_t *out = data;

	if (packet->version == PGP_SEIPD_V2)
	{
		uint32_t chunk_size = 1u << (packet->chunk_size + 6);
		byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
		byte_t iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);

		size_t in_pos = 0;
		size_t out_pos = 0;
		size_t count = 0;

		byte_t tag[PGP_AEAD_TAG_SIZE] = {0};
		byte_t derived_key[48] = {0};
		byte_t info[5] = {0};

		info[0] = packet->header.tag;
		info[1] = packet->version;
		info[2] = packet->symmetric_key_algorithm_id;
		info[3] = packet->aead_algorithm_id;
		info[4] = packet->chunk_size;

		// Derive the message key
		hkdf(HASH_SHA256, session_key, session_key_size, packet->salt, 32, info, 5, derived_key, key_size + iv_size - 8);

		// Decrypt the data paritioned by chunk size + tag size
		while (in_pos < packet->data_size)
		{
			uint32_t in_size = MIN(chunk_size + packet->tag_size, data_size - in_pos);

			// Encrypt the data
			pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size,
							 PTR_OFFSET(derived_key, key_size), (iv_size - 8), info, 5, in + in_pos, in_size, out + out_pos, in_size, tag,
							 PGP_AEAD_TAG_SIZE);

			// Copy the tag to the end
			memcpy(out + in_size, tag, PGP_AEAD_TAG_SIZE);

			in_pos += in_size;
			out_pos += in_size + PGP_AEAD_TAG_SIZE;
			++count;
		}

		// Final authentication tag
		byte_t aad[16] = {0};
		byte_t *pc = (byte_t *)count;

		packet->tag_size = PGP_AEAD_TAG_SIZE;

		// Same as info
		aad[0] = info[0];
		aad[1] = info[1];
		aad[2] = info[2];
		aad[3] = info[3];
		aad[4] = info[4];

		// Store number of chunks as 8 byte big endian
		aad[5] = pc[7];
		aad[6] = pc[6];
		aad[7] = pc[5];
		aad[8] = pc[4];
		aad[9] = pc[3];
		aad[10] = pc[2];
		aad[11] = pc[1];
		aad[12] = pc[0];

		pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size,
						 PTR_OFFSET(derived_key, key_size), (iv_size - 8), aad, 13, NULL, 0, NULL, 0, tag, PGP_AEAD_TAG_SIZE);

		return out_pos;
	}
	else
	{
		// TODO
	}

	return 0;
}

pgp_seipd_packet *pgp_seipd_packet_read(pgp_seipd_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	if (packet->version == PGP_SEIPD_V2)
	{
		void *result;
		byte_t s2k_size = 0;

		// 1 octet symmetric key algorithm
		LOAD_8(&packet->symmetric_key_algorithm_id, in + pos);
		pos += 1;

		// 1 octet AEAD algorithm
		LOAD_8(&packet->aead_algorithm_id, in + pos);
		pos += 1;

		// 1 octet chunk size
		LOAD_8(&packet->chunk_size, in + pos);
		pos += 1;

		// 32-octets of salt
		memcpy(packet->salt, in + pos, 32);
		pos += 32;

		// Data
		packet->data_size = packet->header.body_size - pos - 16;
		memcpy(packet->data, in + pos, packet->data_size);
		pos += packet->data_size;

		// Tag
		packet->tag_size = PGP_AEAD_TAG_SIZE;
		memcpy(packet->tag, in + pos, packet->tag_size);
		pos += packet->tag_size;
	}
	else if (packet->version == PGP_SEIPD_V1)
	{
		// Data
		packet->data_size = packet->header.body_size - 1;
		memcpy(packet->data, in + pos, packet->data_size);
		pos += packet->data_size;
	}
	else
	{
		// Unknown version.
		return NULL;
	}

	return packet;
}

size_t pgp_seipd_packet_write(pgp_seipd_packet *packet, void *ptr, size_t size)
{
	switch (packet->version)
	{
	case PGP_SEIPD_V1:
		return pgp_seipd_packet_v1_write(packet, ptr, size);
	case PGP_SEIPD_V2:
		return pgp_seipd_packet_v2_write(packet, ptr, size);
	}
}
