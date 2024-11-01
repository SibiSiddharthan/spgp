/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>

#include <string.h>

// Refer RFC 9580 - OpenPGP, Section 4.2 Packet Headers

static pgp_packet_header_type get_packet_header_type(void *packet)
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
		if (byte[0] >= 255)
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

byte_t get_packet_header_size(pgp_packet_header_type type, size_t size)
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
	header.header_size = get_packet_header_size(get_packet_header_type(data), size);
	header.body_size = get_packet_body_size(data, size);

	return header;
}

size_t pgp_packet_read(void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);
	pgp_packet_type ptype = pgp_packet_get_type(header.tag);

	if (ptype == PGP_RESERVED || header.body_size == 0)
	{
		return 0;
	}

	if (size < (get_packet_header_size(get_packet_header_type(&header), header.body_size) + header.body_size))
	{
		// Invalid packet
		return 0;
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
		return pgp_ops_packet_read(NULL, data, size);
	case PGP_SECKEY:
		return pgp_secret_key_packet_read(NULL, data, size);
	case PGP_PUBKEY:
		return pgp_public_key_packet_read(NULL, data, size);
	case PGP_SECSUBKEY:
		return pgp_secret_subkey_packet_read(NULL, data, size);
	case PGP_COMP:
		return pgp_compressed_packet_read(NULL, data, size);
	case PGP_SED:
		return pgp_encrypted_packet_read(NULL, data, size);
	case PGP_MARKER:
		return pgp_marker_packet_read(NULL, data, size);
	case PGP_LIT:
		return pgp_literal_packet_read(NULL, data, size);
	case PGP_TRUST:
		return pgp_trust_packet_read(NULL, data, size);
	case PGP_UID:
		return pgp_uid_packet_read(NULL, data, size);
	case PGP_PUBSUBKEY:
		return pgp_public_subkey_packet_read(NULL, data, size);
	case PGP_UAT:
		return pgp_uat_packet_read(NULL, data, size);
	case PGP_SEIPD:
		return pgp_seipd_packet_read(NULL, data, size);
	case PGP_MDC:
		return pgp_mdc_packet_read(NULL, data, size);
	case PGP_PADDING:
		return pgp_padding_packet_read(NULL, data, size);
		break;
	default:
		return 0;
	}
}

uint64_t dump_pgp_packet(void *data, size_t data_size)
{
	return 0;
}

pgp_compresed_packet *pgp_compresed_packet_read(pgp_compresed_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;

	// Get the compression algorithm
	LOAD_8(&packet->compression_algorithm_id, in + pos);
	pos += 1;

	// Copy the compressed data.
	memcpy(packet->data, in + pos, packet->header.body_size - 1);

	return packet;
}

size_t pgp_compresed_packet_write(pgp_compresed_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// 1 octet of compression algorithm
	// N bytes of padding data

	required_size = packet->header.header_size + packet->header.body_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet of compression algorithm
	LOAD_8(out + pos, &packet->compression_algorithm_id);
	pos += 1;

	// Compressed data
	memcpy(out + pos, packet->data, packet->header.body_size - 1);
	pos += packet->header.body_size;

	return pos;
}

pgp_marker_packet *pgp_marker_packet_read(pgp_marker_packet *packet, void *data, size_t size)
{
	byte_t marker[3] = {0x50, 0x47, 0x50};

	// Checks for a valid marker packet.
	if (packet->header.header_size != 2)
	{
		return NULL;
	}

	if (packet->header.body_size != 3)
	{
		return NULL;
	}

	if (memcmp((byte_t *)data + packet->header.header_size, marker, 3) != 0)
	{
		return NULL;
	}

	memcpy(packet->marker, marker, 3);

	return packet;
}

size_t pgp_marker_packet_write(pgp_marker_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// 2 octet header (new and legacy)
	// 3 octets of marker data

	required_size = 2 + 3;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Padding data
	memcpy(out + pos, packet->marker, 3);
	pos += 3;

	return pos;
}

pgp_padding_packet *pgp_padding_packet_read(pgp_padding_packet *packet, void *data, size_t size)
{
	// Copy the padding data.
	memcpy(packet->data, (byte_t *)data + packet->header.header_size, packet->header.body_size);

	return packet;
}

size_t pgp_padding_packet_write(pgp_padding_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// N bytes of padding data

	required_size = packet->header.header_size + packet->header.body_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Padding data
	memcpy(out + pos, packet->data, packet->header.body_size);
	pos += packet->header.body_size;

	return pos;
}

pgp_mdc_packet *pgp_mdc_packet_read(pgp_mdc_packet *packet, void *data, size_t size)
{
	// Checks for a valid modification detection code packet.
	if (packet->header.header_size != 2)
	{
		return NULL;
	}

	if (packet->header.body_size != 20)
	{
		return NULL;
	}

	// Copy the SHA-1 hash
	memcpy(packet->sha1_hash, (byte_t *)data + packet->header.header_size, 20);

	return packet;
}

size_t pgp_mdc_packet_write(pgp_mdc_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// 2 octet header (new and legacy)
	// 20 octets of SHA-1 hash

	required_size = 2 + 3;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Padding data
	memcpy(out + pos, packet->sha1_hash, 20);
	pos += 3;

	return pos;
}
