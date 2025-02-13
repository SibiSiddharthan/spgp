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

	packet->header.tag = pgp_packet_tag(header_format, PGP_COMP, 0);
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

pgp_compresed_packet *pgp_compressed_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_compresed_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;
	uint32_t data_size = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;
	data_size = header.body_size - 1;

	if (pgp_packet_get_type(header.tag) != PGP_COMP)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_compresed_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	packet->data = malloc(data_size);

	if (packet->data == NULL)
	{
		pgp_compressed_packet_delete(packet);
	}

	// Copy the header
	packet->header = header;

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

pgp_marker_packet *pgp_marker_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_marker_packet *packet = NULL;
	pgp_packet_header header = {0};
	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_MARKER)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	// Marker packets have only 3 bytes of marker data
	if (header.body_size != 3)
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_marker_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	// Copy the header
	packet->header = header;

	// Copy the marker data
	packet->marker[0] = in[pos + 0];
	packet->marker[1] = in[pos + 1];
	packet->marker[2] = in[pos + 2];

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

pgp_literal_packet *pgp_literal_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_literal_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_LIT)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_literal_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	// Copy the header
	packet->header = header;

	// 1-octet format specifier
	LOAD_8(&packet->format, in + pos);
	pos += 1;

	// A 1-octet denoting file name length
	LOAD_8(&packet->filename_size, in + pos);
	pos += 1;

	// N-octets of filename
	if (packet->filename_size > 0)
	{
		packet->filename = malloc(packet->filename_size);

		if (packet->filename == NULL)
		{
			pgp_literal_packet_delete(packet);
		}

		memcpy(packet->filename, in + pos, packet->filename_size);
		pos += packet->filename_size;
	}

	// A 4-octet date
	uint32_t date_be;

	LOAD_32(&date_be, in + pos);
	packet->date = BSWAP_32(date_be);
	pos += 4;

	packet->data_size = header.body_size - (4 + 1 + 1 + packet->filename_size);

	// Literal data
	if (packet->data_size > 0)
	{
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			pgp_literal_packet_delete(packet);
		}

		memcpy(packet->data, in + pos, packet->data_size);
		pos += packet->data_size;
	}

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

pgp_user_id_packet *pgp_user_id_packet_new(byte_t header_format, void *user_name, uint16_t user_name_size, void *user_comment,
										   uint16_t user_comment_size, void *user_email, uint16_t user_email_size)
{
	pgp_user_id_packet *packet = NULL;
	size_t required_size = sizeof(pgp_packet_header) + user_name_size + user_comment_size + user_email_size;
	size_t pos = 0;

	// Require user_name atleast
	if (user_name_size == 0)
	{
		return NULL;
	}

	if (user_comment_size > 0)
	{
		required_size += 3; // '(' and ')' and ' '
	}

	if (user_email_size > 0)
	{
		required_size += 3; // '<' and '>' and ' '
	}

	packet = malloc(required_size);

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, required_size);

	packet->header = pgp_encode_packet_header(header_format, PGP_UID, user_name_size + user_comment_size + user_email_size);

	// Data is stored as "user_name (user_comment) <user_email>"
	memcpy(packet->user_data + pos, user_name, user_name_size);
	pos += user_name_size;

	packet->user_data[pos] = ' ';
	pos += 1;

	if (user_comment_size > 0)
	{
		packet->user_data[pos] = '(';
		pos += 1;

		memcpy(packet->user_data + pos, user_comment, user_comment_size);
		pos += user_comment_size;

		packet->user_data[pos] = '(';
		pos += 1;

		if (user_email_size > 0)
		{
			packet->user_data[pos] = ' ';
			pos += 1;
		}
	}

	if (user_email_size > 0)
	{
		packet->user_data[pos] = '<';
		pos += 1;

		memcpy(packet->user_data + pos, user_email, user_email_size);
		pos += user_email_size;

		packet->user_data[pos] = '>';
		pos += 1;
	}

	return packet;
}

void pgp_user_id_packet_delete(pgp_user_id_packet *packet)
{
	free(packet);
}

pgp_user_id_packet *pgp_user_id_packet_read(void *data, size_t size)
{
	pgp_user_id_packet *packet = NULL;
	pgp_packet_header header = {0};

	header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_UID)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_user_id_packet) + header.body_size);

	if (packet == NULL)
	{
		return NULL;
	}

	// Copy the header
	packet->header = header;

	// Copy the user data.
	memcpy(packet->user_data, PTR_OFFSET(data, header.header_size), header.body_size);

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
	memcpy(out + pos, packet->user_data, packet->header.body_size);
	pos += packet->header.body_size;

	return pos;
}

static void *pgp_user_attribute_subpacket_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_packet_header header = {0};
	size_t pos = 0;

	header = pgp_subpacket_header_read(data, size);
	pos = header.header_size;

	if (header.tag == 0)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	switch (header.tag & PGP_SUBPACKET_TAG_MASK)
	{
	case PGP_USER_ATTRIBUTE_IMAGE:
	{
		pgp_user_attribute_image_subpacket *image_subpacket = NULL;
		uint32_t image_size = header.body_size - 16;

		image_subpacket = malloc(sizeof(pgp_user_attribute_image_subpacket) + image_size);

		if (image_subpacket == NULL)
		{
			return NULL;
		}

		// Copy the header
		image_subpacket->header = header;

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
		memset(image_subpacket->reserved, 0, 12);
		pos += 12;

		// N octets of image data
		image_subpacket->image_data = PTR_OFFSET(image_subpacket, sizeof(pgp_user_attribute_image_subpacket));
		memcpy(image_subpacket->image_data, in + pos, image_size);
		pos += image_size;

		return image_subpacket;
	}
	default:
	{
		pgp_unknown_subpacket *subpacket = malloc(sizeof(pgp_unknown_subpacket) + header.body_size);

		if (subpacket == NULL)
		{
			return NULL;
		}

		subpacket->header = header;
		subpacket->data = PTR_OFFSET(subpacket, sizeof(pgp_unknown_subpacket));
		memcpy(subpacket->data, in + pos, header.body_size);

		return subpacket;
	}
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

	pos += pgp_subpacket_header_write(header, ptr);

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
		if ((subpacket_header->tag & PGP_SUBPACKET_TAG_MASK) == PGP_USER_ATTRIBUTE_IMAGE)
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
	packet->subpacket_count += 1;

	packet->header =
		pgp_encode_packet_header(header_format, PGP_UAT, image_subpacket->header.body_size + image_subpacket->header.header_size);

	return packet;
}

pgp_user_attribute_packet *pgp_user_attribute_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_user_attribute_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;
	size_t subpacket_pos = 0;
	uint16_t subpacket_count = 0;
	uint16_t subpacket_size = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_UAT)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_user_attribute_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_user_attribute_packet));

	// Copy the header
	packet->header = header;

	while (subpacket_pos < packet->header.body_size)
	{
		void *subpacket = pgp_user_attribute_subpacket_read(PTR_OFFSET(in, pos), packet->header.body_size - subpacket_pos);
		pgp_subpacket_header *subpacket_header = subpacket;

		if (subpacket == NULL)
		{
			pgp_user_attribute_packet_delete(packet);
			return NULL;
		}

		if (subpacket_count == subpacket_size)
		{

			if (packet->subpackets == NULL)
			{
				subpacket_size += 1;
				packet->subpackets = malloc(sizeof(void *) * subpacket_size);
			}
			else
			{
				subpacket_size *= 2;
				packet->subpackets = realloc(packet->subpackets, sizeof(void *) * subpacket_size);
			}

			if (packet->subpackets == NULL)
			{
				pgp_user_attribute_packet_delete(packet);
				return NULL;
			}
		}

		packet->subpackets[subpacket_count] = subpacket;

		subpacket_pos += subpacket_header->header_size + subpacket_header->body_size;
		pos += subpacket_header->header_size + subpacket_header->body_size;
		subpacket_count += 1;
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

pgp_padding_packet *pgp_padding_packet_read(void *data, size_t size)
{
	pgp_padding_packet *packet = NULL;
	pgp_packet_header header = {0};

	header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_PADDING)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_padding_packet) + header.body_size);

	if (packet == NULL)
	{
		return NULL;
	}

	// Copy the header
	packet->header = header;

	// Copy the padding data.
	memcpy(packet->data, PTR_OFFSET(data, header.header_size), header.body_size);

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

pgp_mdc_packet *pgp_mdc_packet_read(void *data, size_t size)
{
	pgp_mdc_packet *packet = NULL;
	pgp_packet_header header = {0};

	header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_MDC)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	// Checks for a valid modification detection code packet.
	if (header.header_size != 2)
	{
		return NULL;
	}

	if (header.body_size != 20)
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_mdc_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	// Copy the header
	packet->header = header;

	// Copy the SHA-1 hash
	memcpy(packet->sha1_hash, PTR_OFFSET(data, header.header_size), 20);

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

pgp_trust_packet *pgp_trust_packet_new(byte_t header_format, byte_t trust_level)
{
	pgp_trust_packet *packet = malloc(sizeof(pgp_trust_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_trust_packet));
	packet->header = pgp_encode_packet_header(header_format, PGP_TRUST, 1);
	packet->level = trust_level;

	return packet;
}

void pgp_trust_packet_delete(pgp_trust_packet *packet)
{
	free(packet);
}

pgp_trust_packet *pgp_trust_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_trust_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_TRUST)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_trust_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	// Copy the header
	packet->header = header;

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
