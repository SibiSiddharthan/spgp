/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>

// Refer RFC 9580 - OpenPGP, Section 4.2 Packet Headers

pgp_packet_header_type get_packet_header_type(void *packet)
{
	pgp_packet_header *header = packet;
	byte_t tag = header->tag;

	// Bit 6 and 7 are set
	if ((tag & 0xC0) == 0xC0)
	{
		return PGP_HEADER;
	}

	return PGP_LEGACY_HEADER;
}

uint32_t get_packet_size(void *packet)
{
	pgp_packet_header *header = packet;
	byte_t *byte = (byte_t *)packet + 1;

	byte_t tag = header->tag;
	uint32_t size = 0;

	// New format packet
	if ((tag & 0xC0) == 0xC0)
	{
		// 5 octet length
		if (byte[0] >= 255)
		{
			size = ((uint32_t)byte[1] << 24) | ((uint32_t)byte[2] << 16) | ((uint32_t)byte[3] << 8) | (uint32_t)byte[4];
		}
		// 2 octet legnth
		else if (byte[0] >= 192 && byte[0] <= 233)
		{
			size = ((byte[0] - 192) << 8) + byte[1] + 192;
		}
		// 1 octed length
		else if (byte[0] < 192)
		{
			size = byte[0];
		}
		// Partial body length
		else
		{
			size = (uint32_t)1 << (byte[0] & 0x1F);
		}
	}
	else
	{
		switch (tag & 0x3)
		{
		// 1 octed length
		case 0:
			size = byte[0];
			break;
		// 2 octet legnth
		case 1:
			size = (uint32_t)byte[0] << 8 + (uint32_t)byte[1];
			break;
		// 4 octet length
		case 2:
			size = ((uint32_t)byte[0] << 24) | ((uint32_t)byte[1] << 16) | ((uint32_t)byte[2] << 8) | (uint32_t)byte[3];
			break;
		// Legacy partial packets unsupported.
		case 3:
			return 0;
		}
	}

	return size;
}

#if 0
void write_pgp_signature_packet(packet_stream *stream, signature_packet *packet)
{
	// Version 3 packet (obsolete)
	if(packet->version == 3)
	{
		// Header
		write_pgp_packet_header(stream, &packet->header, LEGACY_FORMAT_HEADER);

		// 1 octet version
		ADLOAD_8(stream->current, &packet->version);

		// 1 octet hashed length
		ADLOAD_8(stream->current, &packet->hashed_size_v3);

		// 1 octet signature type
		ADLOAD_8(stream->current, &packet->type);

		// 4 octet timestamp
		uint32_t timestamp = BSWAP_32(packet->timestamp);
		ADLOAD_32(stream->current, &timestamp);

		// 8 octet key-id
		ADLOAD_64(stream->current, &packet->key_id);

		// 1 octet public-key algorithm
		ADLOAD_8(stream->current, &packet->public_key_algorithm_id);

		// 1 octet hash algorithm
		ADLOAD_8(stream->current, &packet->hash_algorithm_id);

		// 2 octets of the left 16 bits of signed hash value
		ADLOAD_16(stream->current, &packet->quick_hash);

		// signature stuff
		
		return;
	}

	// Version 4,6

	return;
}
#endif
