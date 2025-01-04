/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>

#include <stdio.h>
#include <string.h>

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

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

size_t pgp_literal_packet_print(pgp_literal_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	memcpy(PTR_OFFSET(str, pos), "Literal Data Packet (Tag 11)", 28);
	pos += 28;

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

	memcpy(PTR_OFFSET(str, pos), "Format: ", 8);
	pos += 8;

	switch (packet->format)
	{
	case PGP_LITERAL_DATA_BINARY:
		memcpy(PTR_OFFSET(str, pos), "Binary (Tag 0)\n", 15);
		pos += 15;
		break;
	case PGP_LITERAL_DATA_TEXT:
		memcpy(PTR_OFFSET(str, pos), "Text (Tag 1)\n", 13);
		pos += 13;
		break;
	case PGP_LITERAL_DATA_UTF8:
		memcpy(PTR_OFFSET(str, pos), "UTF-8 (Tag 2)\n", 14);
		pos += 14;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown (Tag %hhu)\n", packet->format);
	}

	// TODO format date
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "\nDate: %u\n", packet->date);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Filename (%u bytes): ", packet->filename_size);

	if (packet->filename_size > 0)
	{
		memcpy(PTR_OFFSET(str, pos), packet->filename, packet->filename_size);
		pos += packet->filename_size;
	}

	out[pos] = '\n';
	pos += 1;

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Data (%u bytes)\n", packet->data_size);

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

size_t pgp_user_attribute_packet_print(pgp_user_attribute_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	memcpy(PTR_OFFSET(str, pos), "User Attribute Packet (Tag 17)", 30);
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

	for (uint16_t i = 0; i < packet->subpacket_count; ++i)
	{
		pgp_user_attribute_subpacket_header *subpacket_header = packet->subpackets[i];

		switch (subpacket_header->type)
		{
		case PGP_USER_ATTRIBUTE_IMAGE:
		{
			pgp_user_attribute_image_subpacket *image_subpacket = subpacket_header;
			uint32_t image_size = image_subpacket->header.body_size - 16;

			memcpy(PTR_OFFSET(str, pos), "User Attribute Image Subpacket (Tag 1)\n", 39);
			pos += 39;

			switch (image_subpacket->image_encoding)
			{
			case PGP_USER_ATTRIBUTE_IMAGE_JPEG:
			{
				memcpy(PTR_OFFSET(str, pos), "Image Encoding: JPEG (Tag 1)\n", 30);
				pos += 30;
			}
			break;
			default:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Image Encoding (Tag %hhu)\n", image_subpacket->image_encoding);
			}

			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Image Size: %u bytes\n", image_size);
		}
		break;
		default:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Subpacket (Tag %hhu) (%u bytes)\n", subpacket_header->type,
							subpacket_header->body_size);
		}
	}

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
