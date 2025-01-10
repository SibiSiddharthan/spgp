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

pgp_compresed_packet *pgp_compressed_packet_new(byte_t header_format, byte_t compression_algorithm_id)
{
	pgp_compresed_packet *packet = NULL;

	packet = malloc(sizeof(pgp_compresed_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_compresed_packet));

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
	pgp_packet_header_format header_type = PGP_PACKET_HEADER_FORMAT(packet->header.tag);

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
		packet->header = pgp_encode_packet_header(header_type, PGP_COMP, size + 1);

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

pgp_marker_packet *pgp_marker_packet_new(byte_t header_format)
{
	pgp_marker_packet *packet = malloc(sizeof(pgp_marker_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_marker_packet));

	packet->header = pgp_encode_packet_header(header_format, PGP_MARKER, 3);

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

pgp_literal_packet *pgp_literal_packet_new(byte_t header_format)
{
	pgp_literal_packet *packet = NULL;

	packet = malloc(sizeof(pgp_literal_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_literal_packet));

	packet->header = pgp_encode_packet_header(header_format, PGP_LIT, 0);

	return packet;
}

void pgp_literal_packet_delete(pgp_literal_packet *packet)
{
	free(packet->filename);
	free(packet->data);
	free(packet);
}

size_t pgp_literal_packet_get_filename(pgp_literal_packet *packet, void *filename, size_t size)
{
	if (packet->filename == NULL)
	{
		return 0;
	}

	if (size < packet->filename_size)
	{
		return 0;
	}

	memcpy(filename, packet->filename, packet->filename_size);

	return packet->filename_size;
}

pgp_literal_packet *pgp_literal_packet_set_filename(pgp_literal_packet *packet, void *filename, size_t size)
{
	pgp_packet_header_format header_format = PGP_PACKET_HEADER_FORMAT(packet->header.tag);

	if (size > 255)
	{
		return NULL;
	}

	packet->filename = malloc(size);

	if (packet->filename == NULL)
	{
		return NULL;
	}

	packet->filename_size = size;
	memcpy(packet->filename, filename, size);

	// Update as if no data exists.
	packet->header = pgp_encode_packet_header(header_format, PGP_LIT, 1 + 1 + size);

	return packet;
}

size_t pgp_literal_packet_get_data(pgp_literal_packet *packet, void *data, size_t size)
{
	if (packet->data == NULL)
	{
		return 0;
	}

	if (size < packet->data_size)
	{
		return 0;
	}

	// Just return the data as stored since there is no way to know for sure if we require text conversions.
	memcpy(data, packet->data, packet->data_size);

	return packet->data_size;
}

pgp_literal_packet *pgp_literal_packet_set_data(pgp_literal_packet *packet, pgp_literal_data_format format, uint32_t date, void *data,
												size_t size)
{
	pgp_packet_header_format header_format = PGP_PACKET_HEADER_FORMAT(packet->header.tag);
	size_t required_size = size;
	size_t max_size = (1ull << 32) - (1 + 1 + 4 + packet->filename_size) - 1;

	if (format != PGP_LITERAL_DATA_BINARY && format != PGP_LITERAL_DATA_UTF8 && format != PGP_LITERAL_DATA_TEXT)
	{
		return NULL;
	}

	if (size > max_size)
	{
		return NULL;
	}

	if (format == PGP_LITERAL_DATA_TEXT || format == PGP_LITERAL_DATA_UTF8)
	{
		// Traverse the text data to determine the number of conversions required.
		uint32_t convert_count = 0;
		byte_t *pdata = data;
		byte_t *pout = NULL;

		for (size_t i = 0; i < size; ++i)
		{
			if (i != 0)
			{
				if (pdata[i] == '\n' && pdata[i - 1] != '\r')
				{
					++convert_count;
				}
			}
			else
			{
				if (pdata[i] == '\n')
				{
					++convert_count;
				}
			}
		}

		required_size += convert_count;

		// Make sure the converted text is less than 4GB
		if (required_size > max_size)
		{
			return NULL;
		}

		packet->data = malloc(required_size);

		if (packet->data == NULL)
		{
			return NULL;
		}

		// Copy the data byte by byte, we can't do any better.
		pout = packet->data;
		uint32_t pos = 0;

		for (size_t i = 0; i < size; ++i)
		{
			if (i != 0)
			{
				if (pdata[i] == '\n' && pdata[i - 1] != '\r')
				{
					pout[pos++] = '\r';
					pout[pos++] = '\n';
				}
				else
				{
					pout[pos++] = pdata[i];
				}
			}
			else
			{
				if (pdata[i] == '\n')
				{
					pout[pos++] = '\r';
					pout[pos++] = '\n';
				}
				else
				{
					pout[pos++] = pdata[i];
				}
			}
		}
	}
	else // PGP_LITERAL_DATA_BINARY
	{
		// Just copy the data.
		packet->data = malloc(required_size);

		if (packet->data == NULL)
		{
			return NULL;
		}

		memcpy(packet->data, data, size);
	}

	packet->format = format;
	packet->date = date;
	packet->data_size = required_size;

	packet->header = pgp_encode_packet_header(header_format, PGP_LIT, 1 + 1 + 4 + packet->filename_size + packet->data_size);

	return packet;
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

	packet->header = pgp_encode_packet_header(header_format, PGP_UID, size);
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

static void *pgp_user_attribute_subpacket_read(void *subpacket, void *ptr, size_t size)
{
	pgp_subpacket_header *header = subpacket;
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
	LOAD_8(&header->tag, in + pos);
	pos += 1;

	// Ignore the critical bit
	header->tag &= 0x7F;

	switch (header->tag)
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
	pgp_subpacket_header *header = subpacket;

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
	LOAD_8(out + pos, &header->tag);
	pos += 1;

	switch (header->tag)
	{
	case PGP_USER_ATTRIBUTE_IMAGE:
	{
		pgp_user_attribute_image_subpacket *image_subpacket = subpacket;
		uint32_t image_size = image_subpacket->header.body_size - 16;

		// 2 octets of image length in little endian
		LOAD_16(out + pos, &image_subpacket->image_header_size);
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

pgp_user_attribute_packet *pgp_user_attribute_packet_new(byte_t header_format)
{
	pgp_user_attribute_packet *packet = NULL;

	packet = malloc(sizeof(pgp_user_attribute_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_user_attribute_packet));

	packet->header = pgp_encode_packet_header(header_format, PGP_UAT, 0);

	return packet;
}

void pgp_user_attribute_packet_delete(pgp_user_attribute_packet *packet)
{
	// Free subpackets first.
	for (size_t i = 0; i < packet->subpacket_count; ++i)
	{
		free(packet->subpackets[i]);
	}

	free(packet->subpackets);
	free(packet);
}

size_t pgp_user_attribute_packet_get_image(pgp_user_attribute_packet *packet, void *image, size_t size)
{
	pgp_subpacket_header *subpacket_header = NULL;

	if (packet->subpackets == NULL)
	{
		return 0;
	}

	for (uint16_t i = 0; i < packet->subpacket_count; ++i)
	{
		subpacket_header = packet->subpackets[i];

		// Return the image data of the first image subpacket.
		if ((subpacket_header->tag & 0x7F) == PGP_USER_ATTRIBUTE_IMAGE)
		{
			pgp_user_attribute_image_subpacket *image_subpacket = packet->subpackets[i];
			uint32_t image_size = image_subpacket->header.body_size - 16;

			if (size < image_size)
			{
				return 0;
			}

			memcpy(image, image_subpacket->image_data, image_size);

			return image_size;
		}
	}

	return 0;
}

pgp_user_attribute_packet *pgp_user_attribute_packet_set_image(pgp_user_attribute_packet *packet, byte_t format, void *image, size_t size)
{
	pgp_user_attribute_image_subpacket *image_subpacket = NULL;
	pgp_packet_header_format header_format = PGP_PACKET_HEADER_FORMAT(packet->header.tag);
	size_t required_size = sizeof(pgp_user_attribute_image_subpacket) + size;

	if (format != PGP_USER_ATTRIBUTE_IMAGE_JPEG)
	{
		return NULL;
	}

	// Allocate for atleast one subpacket.
	packet->subpackets = malloc(sizeof(void *));

	if (packet->subpackets == NULL)
	{
		return NULL;
	}

	// Set the image data
	image_subpacket = malloc(required_size);

	if (image_subpacket == NULL)
	{
		return NULL;
	}

	memset(image_subpacket, 0, required_size);

	image_subpacket->image_header_size = 1;
	image_subpacket->image_header_version = 1;
	image_subpacket->image_encoding = format;
	memcpy(image_subpacket->image_data, image, size);

	image_subpacket->header = pgp_encode_subpacket_header(PGP_USER_ATTRIBUTE_IMAGE, 0, 16 + size);

	packet->subpackets[0] = image_subpacket;
	packet->subpacket_count = 1;

	packet->header =
		pgp_encode_packet_header(header_format, PGP_UAT, image_subpacket->header.body_size + image_subpacket->header.header_size);

	return packet;
}

pgp_user_attribute_packet *pgp_user_attribute_packet_read(pgp_user_attribute_packet *packet, void *data, size_t size)
{
	byte_t *in = data;
	size_t pos = packet->header.header_size;
	uint16_t subpacket_count = 0;

	// Count the subpackets first
	while (pos < packet->header.body_size)
	{
		pgp_subpacket_header *header = PTR_OFFSET(in, pos);

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

	packet->header = pgp_encode_packet_header(header_format, PGP_PADDING, size);
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

pgp_mdc_packet *pgp_mdc_packet_new(byte_t header_format)
{
	pgp_mdc_packet *packet = malloc(sizeof(pgp_mdc_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_mdc_packet));
	packet->header = pgp_encode_packet_header(header_format, PGP_MDC, 20);

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
