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

pgp_packet_type pgp_packet_get_type(byte_t tag);

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static size_t pgp_packet_header_print(pgp_packet_header header, void *str, size_t size)
{
	pgp_packet_header_type format = PGP_PACKET_HEADER_FORMAT(header.tag);
	pgp_packet_type type = pgp_packet_get_type(header.tag);

	byte_t *out = str;
	size_t pos = 0;

	switch (type)
	{
	case PGP_PKESK:
		memcpy(PTR_OFFSET(str, pos), "Public Key Encrypted Session Key Packet (Tag 1)", 47);
		pos += 47;
		break;
	case PGP_SIG:
		memcpy(PTR_OFFSET(str, pos), "Signature Packet (Tag 2)", 24);
		pos += 25;
		break;
	case PGP_SKESK:
		memcpy(PTR_OFFSET(str, pos), "Symmetric Key Encrypted Session Key Packet (Tag 3)", 50);
		pos += 51;
		break;
	case PGP_OPS:
		memcpy(PTR_OFFSET(str, pos), "One-Pass Signature Packet (Tag 4)", 33);
		pos += 34;
		break;
	case PGP_SECKEY:
		memcpy(PTR_OFFSET(str, pos), "Secret Key Packet (Tag 5)", 25);
		pos += 26;
		break;
	case PGP_PUBKEY:
		memcpy(PTR_OFFSET(str, pos), "Public Key Packet (Tag 6)", 25);
		pos += 26;
		break;
	case PGP_SECSUBKEY:
		memcpy(PTR_OFFSET(str, pos), "Secret Subkey Packet (Tag 7)", 28);
		pos += 29;
		break;
	case PGP_COMP:
		memcpy(PTR_OFFSET(str, pos), "Compressed Data Packet (Tag 8)", 30);
		pos += 30;
		break;
	case PGP_SED:
		memcpy(PTR_OFFSET(str, pos), "Symmetrically Encrypted Data Packet (Tag 9)", 43);
		pos += 44;
		break;
	case PGP_MARKER:
		memcpy(PTR_OFFSET(str, pos), "Marker Packet (Tag 10)", 22);
		pos += 23;
		break;
	case PGP_LIT:
		memcpy(PTR_OFFSET(str, pos), "Literal Data Packet (Tag 11)", 28);
		pos += 28;
		break;
	case PGP_TRUST:
		memcpy(PTR_OFFSET(str, pos), "Trust Packet (Tag 12)", 21);
		pos += 22;
		break;
	case PGP_UID:
		memcpy(PTR_OFFSET(str, pos), "User ID Packet (Tag 13)", 23);
		pos += 24;
		break;
	case PGP_PUBSUBKEY:
		memcpy(PTR_OFFSET(str, pos), "Public Subkey Packet (Tag 14)", 29);
		pos += 30;
		break;
	case PGP_UAT:
		memcpy(PTR_OFFSET(str, pos), "User Attribute Packet (Tag 17)", 30);
		pos += 31;
		break;
	case PGP_SEIPD:
		memcpy(PTR_OFFSET(str, pos), "Symmetrically Encrypted and Integrity Protected Data Packet (Tag 18)", 68);
		pos += 68;
		break;
	case PGP_MDC:
		memcpy(PTR_OFFSET(str, pos), "Modification Detection Code Packet (Tag 19)", 45);
		pos += 45;
		break;
	case PGP_PADDING:
		memcpy(PTR_OFFSET(str, pos), "Padding Packet (Tag 21)", 23);
		pos += 24;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Packet (Tag %hhu)", header.tag);
	}

	if (format == PGP_LEGACY_HEADER)
	{
		memcpy(PTR_OFFSET(str, pos), " (Old)\n", 7);
		pos += 7;
	}
	else
	{
		out[pos] = '\n';
		pos += 1;
	}

	return pos;
}

size_t pgp_compresed_packet_print(pgp_compresed_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);

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

	pos += pgp_packet_header_print(packet->header, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Marker: %c%c%c\n", packet->marker[0], packet->marker[1], packet->marker[2]);

	return pos;
}

size_t pgp_literal_packet_print(pgp_literal_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);

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

	pos += pgp_packet_header_print(packet->header, str, size);

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

	pos += pgp_packet_header_print(packet->header, str, size);

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

	pos += pgp_packet_header_print(packet->header, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Padding Data (%u bytes)\n", packet->header.body_size);

	return pos;
}

size_t pgp_mdc_packet_print(pgp_mdc_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);

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
