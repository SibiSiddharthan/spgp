/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <key.h>
#include <seipd.h>
#include <session.h>
#include <signature.h>

#include <string.h>
#include <stdlib.h>

// Refer RFC 9580 - OpenPGP, Section 4.2 Packet Headers

static uint32_t get_packet_body_size(void *packet, size_t packet_size)
{
	pgp_packet_header *header = packet;
	byte_t *byte = (byte_t *)packet + 1;

	// Packet size will be atleast 1.
	byte_t tag = header->tag;
	uint32_t size = 0;

	if (packet_size < 2)
	{
		// No size field.
		return 0;
	}

	// New format packet
	if ((tag & 0xC0) == 0xC0)
	{
		// 5 octet length
		if (byte[0] == 255)
		{
			if (packet_size < 6)
			{
				return 0;
			}

			size = (((uint32_t)byte[1] << 24) | ((uint32_t)byte[2] << 16) | ((uint32_t)byte[3] << 8) | (uint32_t)byte[4]);
		}
		// 2 octet legnth
		else if (byte[0] >= 192 && byte[0] <= 233)
		{
			if (packet_size < 3)
			{
				return 0;
			}

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
			size = (packet_size < 3) ? 0 : ((uint32_t)byte[0] << 8) + (uint32_t)byte[1];
			break;
		// 4 octet length
		case 2:
			size = (packet_size < 5) ? 0
									 : ((uint32_t)byte[0] << 24) | ((uint32_t)byte[1] << 16) | ((uint32_t)byte[2] << 8) | (uint32_t)byte[3];
			break;
		// Legacy partial packets unsupported.
		case 3:
			return 0;
		}
	}

	return size;
}

static byte_t get_packet_header_size(pgp_packet_header_format format, size_t size)
{
	if (format == PGP_HEADER)
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

byte_t pgp_packet_tag(pgp_packet_header_format header_type, pgp_packet_type packet_type, uint32_t size)
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

pgp_packet_header pgp_encode_packet_header(pgp_packet_header_format header_format, pgp_packet_type packet_type, size_t body_size)
{
	pgp_packet_header header = {0};

	header.tag = pgp_packet_tag(header_format, packet_type, body_size);
	header.header_size = get_packet_header_size(header_format, body_size);
	header.body_size = body_size;

	return header;
}

pgp_user_attribute_subpacket_header pgp_encode_subpacket_header(pgp_user_attribute_subpacket_type type, size_t body_size)
{
	pgp_user_attribute_subpacket_header header = {0};

	header.type = type;
	header.body_size = body_size;

	// 1,2, or 5 octets of subpacket length
	// 1 octed length
	if (body_size < 192)
	{
		header.header_size = 2;
	}
	// 2 octet legnth
	else if (body_size < 8384)
	{
		header.header_size = 3;
	}
	// 5 octet length
	else
	{
		header.header_size = 6;
	}

	return header;
}

pgp_packet_type pgp_packet_get_type(byte_t tag)
{
	pgp_packet_type ptype = 0;

	// Bit 6 and 7 are set
	if ((tag & 0xC0) == 0xC0)
	{
		ptype = tag & 0x3F;
	}
	else
	{
		ptype = (tag >> 2) & 0x0F;
	}

	switch (ptype)
	{
	case PGP_PKESK:
	case PGP_SIG:
	case PGP_SKESK:
	case PGP_OPS:
	case PGP_SECKEY:
	case PGP_PUBKEY:
	case PGP_SECSUBKEY:
	case PGP_COMP:
	case PGP_SED:
	case PGP_MARKER:
	case PGP_LIT:
	case PGP_TRUST:
	case PGP_UID:
	case PGP_PUBSUBKEY:
	case PGP_UAT:
	case PGP_SEIPD:
	case PGP_MDC:
	case PGP_PADDING:
		break;
	default:
		// Error
		ptype = PGP_RESERVED;
	}

	return ptype;
}

pgp_packet_header pgp_packet_header_read(void *data, size_t size)
{
	byte_t *pdata = data;
	pgp_packet_header header = {0};

	if (size == 0)
	{
		return header;
	}

	header.tag = pdata[0];
	header.header_size = get_packet_header_size(PGP_PACKET_HEADER_FORMAT(header.tag), size);
	header.body_size = get_packet_body_size(data, size);

	return header;
}

uint32_t pgp_packet_header_write(pgp_packet_header *header, void *ptr)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	if (PGP_PACKET_HEADER_FORMAT(header->tag) == PGP_HEADER)
	{
		// 1 byte tag
		LOAD_8(out + pos, &header->tag);
		pos += 1;

		// 1 octed length
		if (header->body_size < 192)
		{
			uint8_t size = (uint8_t)header->body_size;

			LOAD_8(out + pos, &size);
			pos += 1;
		}
		// 2 octet legnth
		else if (header->body_size < 8384)
		{
			uint16_t size = (uint16_t)header->body_size - 192;
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
			uint32_t size = BSWAP_32((uint32_t)header->body_size);

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
		if (header->body_size < 256)
		{
			uint8_t size = (uint8_t)header->body_size;

			LOAD_8(out + pos, &size);
			pos += 1;
		}
		// 2 octet legnth
		else if (header->body_size < 65536)
		{
			uint16_t size = BSWAP_16((uint16_t)header->body_size);

			LOAD_16(out + pos, &size);
			pos += 2;
		}
		// 4 octet length
		else
		{
			uint32_t size = BSWAP_32((uint32_t)header->body_size);

			LOAD_32(out + pos, &size);
			pos += 4;
		}
	}

	return pos;
}

void *pgp_packet_read(void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);
	pgp_packet_type ptype = pgp_packet_get_type(header.tag);

	if (ptype == PGP_RESERVED || header.body_size == 0)
	{
		return NULL;
	}

	if (size < (get_packet_header_size(PGP_PACKET_HEADER_FORMAT(header.tag), header.body_size) + header.body_size))
	{
		// Invalid packet
		return NULL;
	}

	switch (ptype)
	{
	case PGP_PKESK:
		return pgp_pkesk_packet_read(NULL, data, size);
	case PGP_SIG:
		return pgp_signature_packet_read(NULL, data, size);
	case PGP_SKESK:
		return pgp_skesk_packet_read(NULL, data, size);
	case PGP_OPS:
		return pgp_one_pass_signature_packet_read(NULL, data, size);
	case PGP_SECKEY:
		return pgp_secret_key_packet_read(NULL, data, size);
	case PGP_PUBKEY:
		return pgp_public_key_packet_read(NULL, data, size);
	case PGP_SECSUBKEY:
		return pgp_secret_key_packet_read(NULL, data, size);
	case PGP_COMP:
		return pgp_compressed_packet_read(NULL, data, size);
	case PGP_SED:
		return pgp_sed_packet_read(NULL, data, size);
	case PGP_MARKER:
		return pgp_marker_packet_read(NULL, data, size);
	case PGP_LIT:
		return pgp_literal_packet_read(NULL, data, size);
	case PGP_TRUST:
		return pgp_trust_packet_read(NULL, data, size);
	case PGP_UID:
		return pgp_user_id_packet_read(NULL, data, size);
	case PGP_PUBSUBKEY:
		return pgp_public_key_packet_read(NULL, data, size);
	case PGP_UAT:
		return pgp_user_attribute_packet_read(NULL, data, size);
	case PGP_SEIPD:
		return pgp_seipd_packet_read(NULL, data, size);
	case PGP_MDC:
		return pgp_mdc_packet_read(NULL, data, size);
	case PGP_PADDING:
		return pgp_padding_packet_read(NULL, data, size);
		break;
	default:
		return NULL;
	}
}
