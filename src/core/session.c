/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <session.h>
#include <round.h>
#include <string.h>

static uint32_t pgp_session_key_read(pgp_pkesk_packet *packet, void *ptr, uint32_t size)
{
	return 0;
}

static uint32_t pgp_session_key_write(pgp_pkesk_packet *packet, void *ptr)
{
	return 0;
}

static size_t pgp_pkesk_packet_v3_write(pgp_pkesk_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number with value 3.
	// A 8-octet key ID
	// A 1-octet public key algorithm.
	// Session key

	required_size = packet->header.header_size + 1 + 8 + 1 + CEIL_DIV(packet->session_key_bits, 8);

	if (size < required_size)
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

	pos += pgp_session_key_write(packet, out + pos);

	return pos;
}

static size_t pgp_pkesk_packet_v6_write(pgp_pkesk_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number with value 6.
	// A 1-octet length of below 2 fields
	// (Optional) A 1-octet key version.
	// (Optional) A 20/32-octet key fingerprint
	// A 1-octet public key algorithm.
	// Session key

	required_size = packet->header.header_size + 1 + 1 + 1 + packet->anonymous + CEIL_DIV(packet->session_key_bits, 8);

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 1 octet anonymous flag
	LOAD_8(out + pos, &packet->anonymous);
	pos += 1;

	if (packet->anonymous > 0)
	{
		// 1 octet key version
		LOAD_8(out + pos, &packet->key_version);
		pos += 1;

		if ((packet->anonymous - 1) == 32) // V6 key
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

	pos += pgp_session_key_write(packet, out + pos);

	return pos;
}

pgp_pkesk_packet *pgp_pkesk_packet_read(pgp_pkesk_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	if (packet->version == PGP_PKESK_V6)
	{
		// 1 octet anonymous flag
		LOAD_8(&packet->anonymous, in + pos);
		pos += 1;

		if (packet->anonymous > 0)
		{
			// 1 octet key version
			LOAD_8(&packet->key_version, in + pos);
			pos += 1;

			if ((packet->anonymous - 1) == 32) // V6 key
			{
				memcpy(packet->key_fingerprint, in + pos, 32);
				pos += 32;
			}
			else if ((packet->anonymous - 1) == 20) // V4 key
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

	pgp_session_key_read(packet, in + pos, packet->header.body_size - pos);

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

static size_t pgp_skesk_packet_v4_write(pgp_skesk_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number with value 4.
	// A 1-octet symmetric key algorithm.
	// A S2K specifier
	// (Optional) Encrypted Session key

	required_size = packet->header.header_size + 1 + 1 + pgp_s2k_size(&packet->s2k_algorithm) + packet->session_key_size;

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

	// S2K specifier
	pos += pgp_s2k_write(&packet->s2k_algorithm, out + pos);

	// (Optional) Session key
	if (packet->session_key_size > 0)
	{
		memcpy(out + pos, packet->session_key, packet->session_key_size);
		pos += packet->session_key_size;
	}

	return pos;
}

static size_t pgp_skesk_packet_v6_write(pgp_skesk_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	byte_t s2k_size = 0;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number with value 6.
	// A 1-octet count of below 5 fields.
	// A 1-octet symmetric key algorithm.
	// A 1-octet AEAD algorithm.
	// A 1-octet count of below field.
	// A S2K specifier
	// IV
	// Encrypted session key.
	// Authetication key tag.

	s2k_size = pgp_s2k_size(&packet->s2k_algorithm);
	required_size =
		packet->header.header_size + 1 + 1 + 1 + 1 + 1 + s2k_size + packet->iv_size + packet->session_key_size + packet->tag_size;

	if (size < required_size)
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
	pos += pgp_s2k_write(&packet->s2k_algorithm, out + pos);

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

pgp_skesk_packet *pgp_skesk_packet_read(pgp_skesk_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	if (packet->version == PGP_SKESK_V6)
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
		result = pgp_s2k_read(&packet->s2k_algorithm, in + pos, packet->header.body_size - pos);

		if (result == NULL)
		{
			return NULL;
		}

		pos += s2k_size;

		// IV
		packet->iv_size = count - (1 + 1 + 1 + s2k_size);
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
		result = pgp_s2k_read(&packet->s2k_algorithm, in + pos, packet->header.body_size - pos);

		if (result == NULL)
		{
			return NULL;
		}

		pos += pgp_s2k_size(&packet->s2k_algorithm);

		// (Optional) Session key
		packet->session_key_size = packet->header.body_size - pos;

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
		return pgp_skesk_packet_v6_write(packet, ptr, size);
	default:
		return 0;
	}
}
