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
#include <stdio.h>

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

static pgp_packet_header encode_packet_header(pgp_packet_header_type header_format, pgp_packet_type packet_type, size_t body_size)
{
	pgp_packet_header header = {0};

	header.tag = get_tag(header_format, packet_type, body_size);
	header.header_size = get_packet_header_size(header_format, body_size);
	header.body_size = body_size;

	return header;
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

void *pgp_packet_read(void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);
	pgp_packet_type ptype = pgp_packet_get_type(header.tag);

	if (ptype == PGP_RESERVED || header.body_size == 0)
	{
		return NULL;
	}

	if (size < (get_packet_header_size(get_packet_header_type(&header), header.body_size) + header.body_size))
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

pgp_compresed_packet *pgp_compressed_packet_new(byte_t header_format, byte_t compression_algorithm_id)
{
	pgp_compresed_packet *packet = NULL;

	packet = malloc(sizeof(pgp_compresed_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_compresed_packet));

	packet->header.tag = get_tag(header_format, PGP_COMP, 0);
	packet->compression_algorithm_id = compression_algorithm_id;

	return packet;
}

void pgp_compressed_packet_delete(pgp_compresed_packet *packet)
{
	free(packet->data);
	free(packet);
}

pgp_compresed_packet *pgp_compressed_packet_set_data(pgp_compresed_packet *packet, void *ptr, size_t size)
{
	pgp_packet_header_type header_type = get_packet_header_type(packet);

	switch (packet->compression_algorithm_id)
	{
	case PGP_UNCOMPRESSED:
	{
		packet->data = malloc(size);

		if (packet->data == NULL)
		{
			return NULL;
		}

		memcpy(packet->data, ptr, size);

		// Set the header
		packet->header = encode_packet_header(header_type, PGP_COMP, size + 1);

		return packet;
	}
	case PGP_DEFALTE:
	case PGP_ZLIB:
	case PGP_BZIP2:
		// TODO: Implement compression
		return NULL;
	default:
		return NULL;
	}
}

size_t pgp_compressed_packet_get_data(pgp_compresed_packet *packet, void *ptr, size_t size)
{
	size_t uncompressed_data_size = 0;

	switch (packet->compression_algorithm_id)
	{
	case PGP_UNCOMPRESSED:
	{
		uncompressed_data_size = packet->header.body_size - 1;

		if (size < uncompressed_data_size)
		{
			return 0;
		}

		memcpy(ptr, packet->data, uncompressed_data_size);

		return uncompressed_data_size;
	}
	case PGP_DEFALTE:
	case PGP_ZLIB:
	case PGP_BZIP2:
		// TODO: Implement decompression
		return 0;
	default:
		return 0;
	}
}

size_t pgp_compressed_packet_get_raw_data(pgp_compresed_packet *packet, void *ptr, size_t size)
{
	size_t data_size = packet->header.body_size - 1;

	if (size < data_size)
	{
		return 0;
	}

	memcpy(ptr, packet->data, data_size);

	return data_size;
}

pgp_compresed_packet *pgp_compressed_packet_read(pgp_compresed_packet *packet, void *data, size_t size)
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

size_t pgp_compressed_packet_write(pgp_compresed_packet *packet, void *ptr, size_t size)
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

size_t pgp_compresed_packet_print(pgp_compresed_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	memcpy(PTR_OFFSET(str, pos), "Compressed Data Packet (Tag 8)", 30);
	pos += 30;

	if (get_packet_header_type(packet) == PGP_LEGACY_HEADER)
	{
		memcpy(PTR_OFFSET(str, pos), " (Old)\n", 7);
		pos += 7;
	}
	else
	{
		out[pos] = '\n';
		pos += 1;
	}

	memcpy(PTR_OFFSET(str, pos), "Compression Algorithm: ", 23);
	pos += 23;

	switch (packet->compression_algorithm_id)
	{
	case PGP_UNCOMPRESSED:
		memcpy(PTR_OFFSET(str, pos), "Uncompressed (Tag 0)\n", 21);
		pos += 21;
		break;
	case PGP_DEFALTE:
		memcpy(PTR_OFFSET(str, pos), "Deflate (Tag 1)\n", 16);
		pos += 16;
		break;
	case PGP_ZLIB:
		memcpy(PTR_OFFSET(str, pos), "ZLIB (Tag 2)\n", 13);
		pos += 13;
		break;
	case PGP_BZIP2:
		memcpy(PTR_OFFSET(str, pos), "BZIP2 (Tag 3)\n", 14);
		pos += 14;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown (Tag %hhu)\n", packet->compression_algorithm_id);
	}

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Data (%u bytes)\n", packet->header.body_size - 1);

	return pos;
}

pgp_marker_packet *pgp_marker_packet_new(byte_t header_format)
{
	pgp_marker_packet *packet = malloc(sizeof(pgp_marker_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_marker_packet));

	packet->header = encode_packet_header(header_format, PGP_MARKER, 3);

	// Set the marker
	packet->marker[0] = 0x50; // P
	packet->marker[1] = 0x47; // G
	packet->marker[2] = 0x50; // P

	return packet;
}

void pgp_marker_packet_delete(pgp_marker_packet *packet)
{
	free(packet);
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

size_t pgp_marker_packet_print(pgp_marker_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	memcpy(PTR_OFFSET(str, pos), "Marker Packet (Tag 10)", 23);
	pos += 23;

	if (get_packet_header_type(packet) == PGP_LEGACY_HEADER)
	{
		memcpy(PTR_OFFSET(str, pos), " (Old)\n", 7);
		pos += 7;
	}
	else
	{
		out[pos] = '\n';
		pos += 1;
	}

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Marker: %c%c%c\n", packet->marker[0], packet->marker[1], packet->marker[2]);

	return pos;
}

pgp_literal_packet *pgp_literal_packet_read(pgp_literal_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;

	// 1-octet format specifier
	LOAD_8(&packet->format, in + pos);
	pos += 1;

	if (packet->format != PGP_LITERAL_DATA_BINARY && packet->format != PGP_LITERAL_DATA_UTF8 && packet->format != PGP_LITERAL_DATA_TEXT)
	{
		return NULL;
	}

	// A 1-octet denoting file name length
	LOAD_8(&packet->filename_size, in + pos);
	pos += 1;

	// N-octets of filename
	if (packet->filename_size > 0)
	{
		memcpy(packet->filename, in + pos, packet->filename_size);
		pos += packet->filename_size;
	}

	// A 4-octet date
	uint32_t date_be;

	LOAD_32(&date_be, in + pos);
	packet->date = BSWAP_32(date_be);
	pos += 4;

	// Literal data
	memcpy(packet->data, in + pos, packet->data_size);
	pos += packet->data_size;

	return packet;
}

size_t pgp_literal_packet_write(pgp_literal_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet format specifier
	// A 1-octet denoting file name length
	// N-octets of filename
	// A 4-octet date
	// Literal data

	required_size = packet->header.header_size + 1 + 1 + 4 + packet->filename_size + packet->data_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1-octet format specifier
	LOAD_8(out + pos, &packet->format);
	pos += 1;

	// A 1-octet denoting file name length
	LOAD_8(out + pos, &packet->filename_size);
	pos += 1;

	// N-octets of filename
	if (packet->filename_size > 0)
	{
		memcpy(out + pos, packet->filename, packet->filename_size);
		pos += packet->filename_size;
	}

	// A 4-octet date
	uint32_t date = BSWAP_32(packet->date);

	LOAD_32(out + pos, &date);
	pos += 4;

	// Literal data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	return pos;
}

pgp_user_id_packet *pgp_user_id_packet_new(byte_t header_format, void *data, size_t size)
{
	pgp_user_id_packet *packet = NULL;
	size_t required_size = sizeof(pgp_packet_header) + size;

	packet = malloc(required_size);

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, required_size);

	packet->header = encode_packet_header(header_format, PGP_UID, size);
	memcpy(packet->user_id, data, size);

	return packet;
}

void pgp_user_id_packet_delete(pgp_user_id_packet *packet)
{
	free(packet);
}

pgp_user_id_packet *pgp_user_id_packet_read(pgp_user_id_packet *packet, void *data, size_t size)
{
	// Copy the user data.
	memcpy(packet->user_id, (byte_t *)data + packet->header.header_size, packet->header.body_size);

	return packet;
}

size_t pgp_user_id_packet_write(pgp_user_id_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// N bytes of user data

	required_size = packet->header.header_size + packet->header.body_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// User data
	memcpy(out + pos, packet->user_id, packet->header.body_size);
	pos += packet->header.body_size;

	return pos;
}

size_t pgp_user_id_packet_print(pgp_user_id_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	memcpy(PTR_OFFSET(str, pos), "User ID Packet (Tag 13)", 24);
	pos += 24;

	if (get_packet_header_type(packet) == PGP_LEGACY_HEADER)
	{
		memcpy(PTR_OFFSET(str, pos), " (Old)\n", 7);
		pos += 7;
	}
	else
	{
		out[pos] = '\n';
		pos += 1;
	}

	memcpy(PTR_OFFSET(str, pos), "User ID: ", 9);
	pos += 9;

	memcpy(PTR_OFFSET(str, pos), packet->user_id, packet->header.body_size);
	pos += packet->header.body_size;

	out[pos] = '\n';
	pos += 1;

	return pos;
}

static void *pgp_user_attribute_subpacket_read(void *subpacket, void *ptr, size_t size)
{
	pgp_user_attribute_subpacket_header *header = subpacket;
	byte_t *in = ptr;
	size_t pos = 0;

	// 1,2, or 5 octets of subpacket length
	// 5 octet length
	if (in[0] >= 255)
	{
		if (size < 6)
		{
			return NULL;
		}

		header->body_size = (((uint32_t)in[1] << 24) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 8) | (uint32_t)in[4]);
		header->header_size = 5;
	}
	// 2 octet legnth
	else if (in[0] >= 192 && in[0] <= 233)
	{
		if (size < 3)
		{
			return NULL;
		}

		header->body_size = ((in[0] - 192) << 8) + in[1] + 192;
		header->header_size = 2;
	}
	// 1 octed length
	else if (in[0] < 192)
	{
		if (size < 2)
		{
			return NULL;
		}

		header->body_size = in[0];
		header->header_size = 1;
	}

	pos += header->header_size;

	if (size < pos + header->body_size)
	{
		return NULL;
	}

	// 1 octet subpacket type
	LOAD_8(&header->type, in + pos);
	pos += 1;

	switch (header->type)
	{
	case PGP_USER_ATTRIBUTE_IMAGE:
	{
		pgp_user_attribute_image_subpacket *image_subpacket = subpacket;
		uint32_t image_size = image_subpacket->header.body_size - 16;

		// 2 octets of image length in little endian
		LOAD_16(&image_subpacket->image_header_size, in + pos);
		pos += 2;

		// 1 octet image header version
		LOAD_8(&image_subpacket->image_header_version, in + pos);
		pos += 1;

		// 1 octet image encoding
		LOAD_8(&image_subpacket->image_encoding, in + pos);
		pos += 1;

		// 12 octets of reserved zeros
		memset(in + pos, 0, 12);
		pos += 12;

		// N octets of image data
		memcpy(in + pos, image_subpacket->image_data, image_size);
		pos += image_size;

		return image_subpacket;
	}
	default:
		return NULL;
	}

	return NULL;
}

static size_t pgp_user_attribute_subpacket_write(void *subpacket, void *ptr, size_t size)
{
	pgp_user_attribute_subpacket_header *header = subpacket;

	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	required_size = header->header_size + header->body_size;

	if (size < required_size)
	{
		return 0;
	}

	// 1,2, or 5 octets of subpacket length
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

	// 1 octet subpacket type
	LOAD_8(out + pos, &header->type);
	pos += 1;

	switch (header->type)
	{
	case PGP_USER_ATTRIBUTE_IMAGE:
	{
		pgp_user_attribute_image_subpacket *image_subpacket = subpacket;
		uint32_t image_size = image_subpacket->header.body_size - 16;

		// 2 octets of image length in little endian
		LOAD_16(out + pos, image_subpacket->image_header_size);
		pos += 2;

		// 1 octet image header version
		LOAD_8(out + pos, &image_subpacket->image_header_version);
		pos += 1;

		// 1 octet image encoding
		LOAD_8(out + pos, &image_subpacket->image_encoding);
		pos += 1;

		// 12 octets of reserved zeros
		memset(out + pos, 0, 12);
		pos += 12;

		// N octets of image data
		memcpy(out + pos, image_subpacket->image_data, image_size);
		pos += image_size;
	}
	break;
	}

	return pos;
}

pgp_user_attribute_packet *pgp_user_attribute_packet_read(pgp_user_attribute_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;
	uint16_t subpacket_count = 0;

	// Count the subpackets first
	while (pos < packet->header.body_size)
	{
		pgp_user_attribute_subpacket_header *header = PTR_OFFSET(in, pos);

		header = pgp_user_attribute_subpacket_read(header, in + pos, packet->header.body_size - pos);

		if (header == NULL)
		{
			return NULL;
		}

		packet->subpackets[subpacket_count++] = header;
		pos += header->header_size + header->body_size;
	}

	packet->subpacket_count = subpacket_count;

	return packet;
}

size_t pgp_user_attribute_packet_write(pgp_user_attribute_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	required_size = packet->header.header_size + packet->header.body_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Subpackets
	for (uint16_t i = 0; i < packet->subpacket_count; ++i)
	{
		pos += pgp_user_attribute_subpacket_write(packet->subpackets[i], out + pos, size - pos);
	}

	return pos;
}

pgp_padding_packet *pgp_padding_packet_new(byte_t header_format, void *data, size_t size)
{
	pgp_padding_packet *packet = NULL;
	size_t required_size = sizeof(pgp_packet_header) + size;

	packet = malloc(required_size);

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, required_size);

	packet->header = encode_packet_header(header_format, PGP_PADDING, size);
	memcpy(packet->data, data, size);

	return packet;
}

void pgp_padding_packet_delete(pgp_padding_packet *packet)
{
	free(packet);
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

size_t pgp_padding_packet_print(pgp_padding_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	memcpy(PTR_OFFSET(str, pos), "Padding Packet (Tag 21)", 23);
	pos += 23;

	if (get_packet_header_type(packet) == PGP_LEGACY_HEADER)
	{
		memcpy(PTR_OFFSET(str, pos), " (Old)\n", 7);
		pos += 7;
	}
	else
	{
		out[pos] = '\n';
		pos += 1;
	}

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Padding Data (%u bytes)\n", packet->header.body_size);

	return pos;
}

pgp_mdc_packet *pgp_mdc_packet_new(byte_t header_format)
{
	pgp_mdc_packet *packet = malloc(sizeof(pgp_mdc_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_mdc_packet));
	packet->header = encode_packet_header(header_format, PGP_MDC, 20);

	return packet;
}

void pgp_mdc_packet_delete(pgp_mdc_packet *packet)
{
	free(packet);
}

void pgp_mdc_packet_get_hash(pgp_mdc_packet *packet, byte_t hash[20])
{
	memcpy(hash, packet->sha1_hash, 20);
}

void pgp_mdc_packet_set_hash(pgp_mdc_packet *packet, byte_t hash[20])
{
	memcpy(packet->sha1_hash, hash, 20);
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

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

size_t pgp_mdc_packet_print(pgp_mdc_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	memcpy(PTR_OFFSET(str, pos), "Modification Detection Code Packet (Tag 19)", 43);
	pos += 43;

	if (get_packet_header_type(packet) == PGP_LEGACY_HEADER)
	{
		memcpy(PTR_OFFSET(str, pos), " (Old)\n", 7);
		pos += 7;
	}
	else
	{
		out[pos] = '\n';
		pos += 1;
	}

	memcpy(PTR_OFFSET(str, pos), "SHA-1 Hash: ", 12);
	pos += 12;

	for (uint8_t i = 0; i < 20; ++i)
	{
		byte_t a, b;

		a = packet->sha1_hash[i] / 16;
		b = packet->sha1_hash[i] % 16;

		out[pos++] = hex_table[a];
		out[pos++] = hex_table[b];
	}

	out[pos] = '\n';
	pos += 1;

	return pos;
}

pgp_trust_packet *pgp_trust_packet_read(pgp_trust_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;

	LOAD_8(&packet->level, in + pos);
	pos += 1;

	return packet;
}

size_t pgp_trust_packet_write(pgp_trust_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	required_size = packet->header.header_size + 1;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Trust level
	LOAD_8(out + pos, &packet->level);
	pos += 1;

	return pos;
}
