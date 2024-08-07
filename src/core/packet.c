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
			size = ((uint32_t)byte[0] << 8) + (uint32_t)byte[1];
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

uint32_t get_header_size(pgp_packet_header_type type, size_t size)
{
	if (type == PGP_HEADER)
	{
		// New format packet lengths
		// 1 octed length
		if (size < 192)
		{
			return 1 + 1;
		}
		// 2 octet legnth
		else if (size < 8384)
		{
			return 1 + 2;
		}
		// 5 octet length
		else
		{
			return 1 + 5;
		}
	}
	else
	{
		// Legacy format packet lengths
		// 1 octed length
		if (size < 256)
		{
			return 1 + 1;
		}
		// 2 octet legnth
		else if (size < 65536)
		{
			return 1 + 2;
		}
		// 4 octet length
		else
		{
			return 1 + 4;
		}
	}
}

byte_t get_tag(pgp_packet_header_type header_type, pgp_packet_type packet_type, size_t size)
{
	byte_t tag = 0;
	if (header_type == PGP_HEADER)
	{
		tag = 0xC0 | (byte_t)packet_type;
	}
	else
	{
		// Old format packet
		tag = 0x80 | ((byte_t)packet_type << 2);

		// 1 octed length
		if (size < 256)
		{
			tag |= 0;
		}
		// 2 octet legnth
		else if (size < 65536)
		{
			tag |= 1;
		}
		// 4 octet length
		else
		{
			tag |= 2;
		}
	}

	return tag;
}

uint32_t pgp_packet_header_write(pgp_packet_header *header, void *ptr)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	if (get_packet_header_type(header) == PGP_HEADER)
	{
		// 1 byte tag
		LOAD_8(out + pos, &header->tag);
		pos += 1;

		// 1 octed length
		if (header->size < 192)
		{
			uint8_t size = (uint8_t)header->size;

			LOAD_8(out + pos, &size);
			pos += 1;
		}
		// 2 octet legnth
		else if (header->size < 8384)
		{
			uint16_t size = (uint16_t)header->size - 192;
			uint8_t o1 = (size >> 8) + 192;
			uint8_t o2 = (size & 0xFF);

			LOAD_8(out + pos, &o1);
			pos += 1;

			LOAD_8(out + pos, &o2);
			pos += 1;
		}
		// 5 octet length
		else
		{
			// 1st octet is 255
			uint8_t byte = 255;
			uint32_t size = BSWAP_32((uint32_t)header->size);

			LOAD_8(out + pos, &byte);
			pos += 1;

			LOAD_32(out + pos, &size);
			pos += 4;
		}
	}
	else
	{
		// 1 byte tag.
		LOAD_8(out + pos, &header->tag);
		pos += 1;

		// 1 octed length
		if (header->size < 256)
		{
			uint8_t size = (uint8_t)header->size;

			LOAD_8(out + pos, &size);
			pos += 1;
		}
		// 2 octet legnth
		else if (header->size < 65536)
		{
			uint16_t size = BSWAP_16((uint16_t)header->size);

			LOAD_16(out + pos, &size);
			pos += 2;
		}
		// 4 octet length
		else
		{
			uint32_t size = BSWAP_32((uint32_t)header->size);

			LOAD_32(out + pos, &size);
			pos += 4;
		}
	}

	return pos;
}
