/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
#include <algorithms.h>
#include <packet.h>
#include <key.h>
#include <seipd.h>
#include <session.h>
#include <signature.h>
#include <stream.h>
#include <crypto.h>

#include <string.h>
#include <stdlib.h>

static void pgp_compressed_packet_encode_header(pgp_compresed_packet *packet, pgp_packet_header_format header_format)
{
	uint32_t body_size = 0;

	if (header_format == 0)
	{
		header_format = PGP_PACKET_HEADER_FORMAT(packet->header.tag);
	}

	// 1 octet of compression algorithm
	// N bytes of compressed data

	body_size = 1 + packet->data_size;
	packet->header = pgp_encode_packet_header(header_format, PGP_COMP, body_size);
}

pgp_error_t pgp_compressed_packet_new(pgp_compresed_packet **packet, byte_t header_format, byte_t compression_algorithm_id)
{
	pgp_compresed_packet *compressed = NULL;

	if (header_format != PGP_HEADER && header_format != PGP_LEGACY_HEADER)
	{
		return PGP_INVALID_HEADER_FORMAT;
	}

	if (compression_algorithm_id != PGP_UNCOMPRESSED && compression_algorithm_id != PGP_DEFALTE && compression_algorithm_id != PGP_ZLIB &&
		compression_algorithm_id != PGP_BZIP2)
	{
		return PGP_UNKNOWN_COMPRESSION_ALGORITHM;
	}

	compressed = malloc(sizeof(pgp_compresed_packet));

	if (compressed == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(compressed, 0, sizeof(pgp_compresed_packet));

	compressed->compression_algorithm_id = compression_algorithm_id;
	pgp_compressed_packet_encode_header(compressed, header_format);

	*packet = compressed;

	return PGP_SUCCESS;
}

void pgp_compressed_packet_delete(pgp_compresed_packet *packet)
{
	free(packet->data);
	free(packet);
}

pgp_compresed_packet *pgp_compressed_packet_compress_data(pgp_compresed_packet *packet, void *ptr, size_t size)
{

	switch (packet->compression_algorithm_id)
	{
	case PGP_UNCOMPRESSED:
	{
		packet->data = malloc(size);

		if (packet->data == NULL)
		{
			return NULL;
		}

		packet->data_size = size;
		memcpy(packet->data, ptr, size);

		// Set the header
		pgp_compressed_packet_encode_header(packet, 0);

		return packet;
	}
	case PGP_DEFALTE:
	case PGP_ZLIB:
	case PGP_BZIP2:
	{
		// TODO: Implement compression
		packet->header.error = PGP_UNSUPPORTED_COMPRESSION_ALGORITHM;
		return packet;
	}
	default:
	{
		packet->header.error = PGP_UNKNOWN_COMPRESSION_ALGORITHM;
		return packet;
	}
	}
}

size_t pgp_compressed_packet_decompress_data(pgp_compresed_packet *packet, void *ptr, size_t size)
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
	{
		// TODO: Implement compression
		packet->header.error = PGP_UNSUPPORTED_COMPRESSION_ALGORITHM;
		return 0;
	}
	default:
	{
		packet->header.error = PGP_UNKNOWN_COMPRESSION_ALGORITHM;
		return 0;
	}
	}
}

static pgp_error_t pgp_compressed_packet_read_body(pgp_compresed_packet *packet, buffer_t *buffer)
{
	packet->data_size = packet->header.body_size - 1;
	packet->data = malloc(packet->data_size);

	if (packet->data == NULL)
	{
		return PGP_NO_MEMORY;
	}

	// 1 octet compression algorithm
	CHECK_READ(read8(buffer, &packet->compression_algorithm_id), PGP_MALFORMED_COMPRESSED_PACKET);

	// Copy the compressed data.
	CHECK_READ(readn(buffer, packet->data, packet->data_size), PGP_MALFORMED_COMPRESSED_PACKET);

	return PGP_SUCCESS;
}

pgp_error_t pgp_compressed_packet_read_with_header(pgp_compresed_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_compresed_packet *compressed = NULL;

	compressed = malloc(sizeof(pgp_compresed_packet));

	if (compressed == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(compressed, 0, sizeof(pgp_compresed_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	compressed->header = *header;

	// Read the body
	error = pgp_compressed_packet_read_body(compressed, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_compressed_packet_delete(compressed);
		return error;
	}

	*packet = compressed;

	return error;
}

pgp_error_t pgp_compressed_packet_read(pgp_compresed_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_COMP)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_compressed_packet_read_with_header(packet, &header, data);
}

size_t pgp_compressed_packet_write(pgp_compresed_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
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

pgp_error_t pgp_marker_packet_new(pgp_marker_packet **packet, byte_t header_format)
{
	pgp_marker_packet *marker = NULL;

	if (header_format != PGP_HEADER && header_format != PGP_LEGACY_HEADER)
	{
		return PGP_INVALID_HEADER_FORMAT;
	}

	marker = malloc(sizeof(pgp_marker_packet));

	if (marker == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(packet, 0, sizeof(pgp_marker_packet));

	// 3 octets of marker
	marker->header = pgp_encode_packet_header(header_format, PGP_MARKER, 3);

	// Set the marker
	marker->marker[0] = 0x50; // P
	marker->marker[1] = 0x47; // G
	marker->marker[2] = 0x50; // P

	*packet = marker;

	return PGP_SUCCESS;
}

void pgp_marker_packet_delete(pgp_marker_packet *packet)
{
	free(packet);
}

pgp_error_t pgp_marker_packet_read_with_header(pgp_marker_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_marker_packet *marker = NULL;

	byte_t *in = data;
	size_t pos = header->header_size;

	// Marker packets have only 3 bytes of marker data
	if (header->body_size != 3)
	{
		return PGP_MALFORMED_MARKER_PACKET;
	}

	marker = malloc(sizeof(pgp_marker_packet));

	if (marker == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(marker, 0, sizeof(pgp_marker_packet));

	// Copy the header
	marker->header = *header;

	// Copy the marker data
	marker->marker[0] = in[pos + 0];
	marker->marker[1] = in[pos + 1];
	marker->marker[2] = in[pos + 2];

	*packet = marker;

	return PGP_SUCCESS;
}

pgp_error_t pgp_marker_packet_read(pgp_marker_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_MARKER)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	return pgp_marker_packet_read_with_header(packet, &header, data);
}

size_t pgp_marker_packet_write(pgp_marker_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
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

static void pgp_literal_packet_encode_header(pgp_literal_packet *packet, pgp_packet_header_format header_format)
{
	uint32_t body_size = 0;

	if (header_format == 0)
	{
		header_format = PGP_PACKET_HEADER_FORMAT(packet->header.tag);
	}

	// A 1-octet format specifier
	// A 1-octet denoting file name length
	// N-octets of filename
	// A 4-octet date
	// Literal data

	body_size = 1 + 1 + 4 + packet->filename_size + packet->data_size;
	packet->header = pgp_encode_packet_header(header_format, PGP_LIT, body_size);
}

pgp_error_t pgp_literal_packet_new(pgp_literal_packet **packet, byte_t header_format, uint32_t date, void *filename, byte_t filename_size)
{
	pgp_literal_packet *literal = NULL;

	if (header_format != PGP_HEADER && header_format != PGP_LEGACY_HEADER)
	{
		return PGP_INVALID_HEADER_FORMAT;
	}

	literal = malloc(sizeof(pgp_literal_packet));

	if (literal == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(literal, 0, sizeof(pgp_literal_packet));

	// Set the timestamp
	literal->date = date;

	// Copy the filename
	if (filename != NULL && filename_size != 0)
	{
		literal->filename = malloc(filename_size);

		if (literal->filename == NULL)
		{
			pgp_literal_packet_delete(literal);
			return PGP_NO_MEMORY;
		}

		memcpy(literal->filename, filename, filename_size);
		literal->filename_size = filename_size;
	}

	pgp_literal_packet_encode_header(literal, header_format);

	*packet = literal;

	return PGP_SUCCESS;
}

void pgp_literal_packet_delete(pgp_literal_packet *packet)
{
	free(packet->filename);
	free(packet->data);
	free(packet);
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

pgp_error_t pgp_literal_packet_set_data(pgp_literal_packet *packet, pgp_literal_data_format format, void *data, size_t size)
{
	size_t required_size = size;

	if (format != PGP_LITERAL_DATA_BINARY && format != PGP_LITERAL_DATA_LOCAL && format != PGP_LITERAL_DATA_MIME &&
		format != PGP_LITERAL_DATA_TEXT && format != PGP_LITERAL_DATA_UTF8)
	{
		return PGP_UNKNOWN_LITERAL_FORMAT;
	}

	if (format == PGP_LITERAL_DATA_TEXT || format == PGP_LITERAL_DATA_UTF8 || format == PGP_LITERAL_DATA_MIME)
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
		packet->data = malloc(required_size);

		if (packet->data == NULL)
		{
			return PGP_NO_MEMORY;
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
	else // PGP_LITERAL_DATA_BINARY || PGP_LITERAL_DATA_LOCAL
	{
		// Just copy the data.
		packet->data = malloc(required_size);

		if (packet->data == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memcpy(packet->data, data, size);
	}

	packet->format = format;
	packet->data_size = required_size;

	pgp_literal_packet_encode_header(packet, 0);

	return PGP_SUCCESS;
}

static pgp_error_t pgp_literal_packet_read_body(pgp_literal_packet *packet, buffer_t *buffer)
{
	// 1-octet format specifier
	CHECK_READ(read8(buffer, &packet->format), PGP_MALFORMED_LITERAL_PACKET);

	// A 1-octet denoting file name length
	CHECK_READ(read8(buffer, &packet->filename_size), PGP_MALFORMED_LITERAL_PACKET);

	// N-octets of filename
	if (packet->filename_size > 0)
	{
		packet->filename = malloc(packet->filename_size);

		if (packet->filename == NULL)
		{
			return PGP_NO_MEMORY;
		}

		CHECK_READ(readn(buffer, packet->filename, packet->filename_size), PGP_LITERAL_PACKET_INVALID_FILENAME_SIZE);
	}

	// A 4-octet date
	CHECK_READ(read32_be(buffer, &packet->date), PGP_MALFORMED_LITERAL_PACKET);

	packet->data_size = packet->header.body_size - (4 + 1 + 1 + packet->filename_size);

	// Literal data
	if (packet->data_size > 0)
	{
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			return PGP_NO_MEMORY;
		}

		CHECK_READ(readn(buffer, packet->data, packet->data_size), PGP_MALFORMED_LITERAL_PACKET);
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_literal_packet_read_with_header(pgp_literal_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_literal_packet *literal = NULL;

	literal = malloc(sizeof(pgp_literal_packet));

	if (literal == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(literal, 0, sizeof(pgp_literal_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	literal->header = *header;

	// Read the body
	error = pgp_literal_packet_read_body(literal, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_literal_packet_delete(literal);
		return error;
	}

	*packet = literal;

	return error;
}

pgp_error_t pgp_literal_packet_read(pgp_literal_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_LIT)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_literal_packet_read_with_header(packet, &header, data);
}

size_t pgp_literal_packet_write(pgp_literal_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
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

pgp_error_t pgp_user_id_packet_new(pgp_user_id_packet **packet, byte_t header_format, void *user_name, uint16_t user_name_size,
								   void *user_comment, uint16_t user_comment_size, void *user_email, uint16_t user_email_size)
{
	pgp_user_id_packet *uid = NULL;
	size_t required_size = sizeof(pgp_packet_header) + user_name_size + user_comment_size + user_email_size;
	size_t pos = 0;

	if (header_format != PGP_HEADER && header_format != PGP_LEGACY_HEADER)
	{
		return PGP_INVALID_HEADER_FORMAT;
	}

	// Require user_name atleast
	if (user_name_size == 0)
	{
		return PGP_INVALID_USER_ID;
	}

	if (user_comment_size > 0)
	{
		required_size += 3; // '(' and ')' and ' '
	}

	if (user_email_size > 0)
	{
		required_size += 3; // '<' and '>' and ' '
	}

	uid = malloc(required_size);

	if (uid == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(uid, 0, required_size);

	// N octets of user data
	uid->header = pgp_encode_packet_header(header_format, PGP_UID, user_name_size + user_comment_size + user_email_size);

	// Data is stored as "user_name (user_comment) <user_email>"
	memcpy(uid->user_data + pos, user_name, user_name_size);
	pos += user_name_size;

	uid->user_data[pos] = ' ';
	pos += 1;

	if (user_comment_size > 0)
	{
		uid->user_data[pos] = '(';
		pos += 1;

		memcpy(uid->user_data + pos, user_comment, user_comment_size);
		pos += user_comment_size;

		uid->user_data[pos] = '(';
		pos += 1;

		if (user_email_size > 0)
		{
			uid->user_data[pos] = ' ';
			pos += 1;
		}
	}

	if (user_email_size > 0)
	{
		uid->user_data[pos] = '<';
		pos += 1;

		memcpy(uid->user_data + pos, user_email, user_email_size);
		pos += user_email_size;

		uid->user_data[pos] = '>';
		pos += 1;
	}

	*packet = uid;

	return PGP_SUCCESS;
}

void pgp_user_id_packet_delete(pgp_user_id_packet *packet)
{
	free(packet);
}

pgp_error_t pgp_user_id_packet_read_with_header(pgp_user_id_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_user_id_packet *uid = NULL;

	uid = malloc(sizeof(pgp_user_id_packet) + header->body_size);

	if (uid == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(uid, 0, sizeof(pgp_user_id_packet) + header->body_size);

	// Copy the header
	uid->header = *header;

	// Copy the user data.
	memcpy(uid->user_data, PTR_OFFSET(data, header->header_size), header->body_size);

	*packet = uid;

	return PGP_SUCCESS;
}

pgp_error_t pgp_user_id_packet_read(pgp_user_id_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_UID)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_user_id_packet_read_with_header(packet, &header, data);
}

size_t pgp_user_id_packet_write(pgp_user_id_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
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

static pgp_error_t pgp_user_attribute_subpacket_read(void **subpacket, buffer_t *buffer)
{
	pgp_subpacket_header header = pgp_subpacket_header_read(buffer->data + buffer->pos, buffer->size - buffer->pos);

	if (header.tag == 0)
	{
		return PGP_INVALID_USER_ATTRIBUTE_SUBPACKET_TAG;
	}

	if (buffer->size - buffer->pos < PGP_SUBPACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	buffer->pos += header.header_size;

	switch (header.tag & PGP_SUBPACKET_TAG_MASK)
	{
	case PGP_USER_ATTRIBUTE_IMAGE:
	{
		pgp_user_attribute_image_subpacket *image_subpacket = NULL;
		uint32_t image_size = header.body_size - 16;

		image_subpacket = malloc(sizeof(pgp_user_attribute_image_subpacket) + image_size);

		if (image_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(image_subpacket, 0, sizeof(pgp_user_attribute_image_subpacket) + image_size);

		// Copy the header
		image_subpacket->header = header;

		// 2 octets of image length in little endian
		CHECK_READ(read16(buffer, &image_subpacket->image_header_size), PGP_MALFORMED_USER_ATTRIBUTE_IMAGE);

		// 1 octet image header version
		CHECK_READ(read8(buffer, &image_subpacket->image_header_version), PGP_MALFORMED_USER_ATTRIBUTE_IMAGE);

		// 1 octet image encoding
		CHECK_READ(read8(buffer, &image_subpacket->image_encoding), PGP_MALFORMED_USER_ATTRIBUTE_IMAGE);

		// 12 octets of reserved zeros
		memset(image_subpacket->reserved, 0, 12);
		buffer->pos += 12;

		// N octets of image data
		image_subpacket->image_data = PTR_OFFSET(image_subpacket, sizeof(pgp_user_attribute_image_subpacket));
		CHECK_READ(readn(buffer, image_subpacket->image_data, image_size), PGP_MALFORMED_USER_ATTRIBUTE_IMAGE);

		*subpacket = image_subpacket;

		return PGP_SUCCESS;
	}
	case PGP_USER_ATTRIBUTE_UID:
	{
		pgp_user_attribute_uid_subpacket *uid_subpacket = NULL;
		uint32_t uid_size = header.body_size;

		uid_subpacket = malloc(sizeof(pgp_subpacket_header) + uid_size);

		if (uid_subpacket == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(uid_subpacket, 0, sizeof(pgp_subpacket_header) + uid_size);

		// Copy the header
		uid_subpacket->header = header;

		// Copy the UID
		CHECK_READ(readn(buffer, uid_subpacket->user_data, uid_size), PGP_MALFORMED_USER_ATTRIBUTE_ID);

		*subpacket = uid_subpacket;

		return PGP_SUCCESS;
	}
	default:
	{
		pgp_unknown_subpacket *unknown = malloc(sizeof(pgp_unknown_subpacket) + header.body_size);

		if (unknown == NULL)
		{
			return PGP_NO_MEMORY;
		}

		unknown->header = header;
		unknown->data = PTR_OFFSET(unknown, sizeof(pgp_unknown_subpacket));
		CHECK_READ(readn(buffer, unknown->data, header.body_size), PGP_INSUFFICIENT_DATA);

		*subpacket = unknown;

		return PGP_SUCCESS;
	}
	}

	return PGP_SUCCESS;
}

static size_t pgp_user_attribute_subpacket_write(void *subpacket, void *ptr, size_t size)
{
	pgp_subpacket_header *header = subpacket;

	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_SUBPACKET_OCTETS(*header))
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
	case PGP_USER_ATTRIBUTE_UID:
	{
		pgp_user_attribute_uid_subpacket *uid_subpacket = subpacket;
		uint32_t uid_size = uid_subpacket->header.body_size;

		// N octets of UID
		memcpy(out + pos, uid_subpacket->user_data, uid_size);
		pos += uid_size;
	}
	break;
	}

	return pos;
}

static void pgp_user_attribute_encode_header(pgp_user_attribute_packet *packet)
{
	// N octets of subpackets
	packet->header = pgp_encode_packet_header(PGP_HEADER, PGP_UAT, packet->subpacket_octets);
}

pgp_error_t pgp_user_attribute_packet_new(pgp_user_attribute_packet **packet)
{
	pgp_user_attribute_packet *uat = NULL;

	uat = malloc(sizeof(pgp_user_attribute_packet));

	if (uat == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(uat, 0, sizeof(pgp_user_attribute_packet));

	*packet = uat;

	return PGP_SUCCESS;
}

void pgp_user_attribute_packet_delete(pgp_user_attribute_packet *packet)
{
	// Free subpackets first.
	pgp_stream_delete(packet->subpackets);
	free(packet);
}

size_t pgp_user_attribute_packet_get_image(pgp_user_attribute_packet *packet, void *image, size_t size)
{
	pgp_subpacket_header *subpacket_header = NULL;

	if (packet->subpackets == NULL)
	{
		return 0;
	}

	for (uint16_t i = 0; i < packet->subpackets->count; ++i)
	{
		subpacket_header = packet->subpackets->packets[i];

		// Return the image data of the first image subpacket.
		if ((subpacket_header->tag & PGP_SUBPACKET_TAG_MASK) == PGP_USER_ATTRIBUTE_IMAGE)
		{
			pgp_user_attribute_image_subpacket *image_subpacket = packet->subpackets->packets[i];
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
	void *result = NULL;

	pgp_user_attribute_image_subpacket *image_subpacket = NULL;
	size_t required_size = sizeof(pgp_user_attribute_image_subpacket) + size;

	if (format != PGP_USER_ATTRIBUTE_IMAGE_JPEG)
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

	result = pgp_stream_push_packet(packet->subpackets, image_subpacket);

	if (result == NULL)
	{
		pgp_user_attribute_packet_delete(packet);
		return NULL;
	}

	packet->subpackets = result;
	packet->subpacket_octets += PGP_SUBPACKET_OCTETS(image_subpacket->header);

	pgp_user_attribute_encode_header(packet);

	return packet;
}

size_t pgp_user_attribute_packet_get_uid(pgp_user_attribute_packet *packet, void *data, size_t size)
{
	pgp_subpacket_header *subpacket_header = NULL;

	if (packet->subpackets == NULL)
	{
		return 0;
	}

	for (uint16_t i = 0; i < packet->subpackets->count; ++i)
	{
		subpacket_header = packet->subpackets->packets[i];

		// Return the image data of the first image subpacket.
		if ((subpacket_header->tag & PGP_SUBPACKET_TAG_MASK) == PGP_USER_ATTRIBUTE_UID)
		{
			pgp_user_attribute_uid_subpacket *uid_subpacket = packet->subpackets->packets[i];
			uint32_t uid_size = uid_subpacket->header.body_size;

			if (size < uid_size)
			{
				return 0;
			}

			memcpy(data, uid_subpacket->user_data, uid_size);

			return uid_size;
		}
	}

	return 0;
}

pgp_user_attribute_packet *pgp_user_attribute_packet_set_uid(pgp_user_attribute_packet *packet, void *user_name, uint16_t user_name_size,
															 void *user_comment, uint16_t user_comment_size, void *user_email,
															 uint16_t user_email_size)
{
	void *result = NULL;

	pgp_user_attribute_uid_subpacket *uid_subpacket = NULL;
	pgp_user_id_packet *uid_packet = NULL;

	pgp_user_id_packet_new(&uid_packet, PGP_HEADER, user_name, user_name_size, user_comment, user_comment_size, user_email,
						   user_email_size);

	if (uid_packet == NULL)
	{
		return NULL;
	}

	// Layout is the same. Just change the tag.
	uid_subpacket = (pgp_user_attribute_uid_subpacket *)uid_packet;
	uid_subpacket->header.tag = PGP_USER_ATTRIBUTE_UID;

	result = pgp_stream_push_packet(packet->subpackets, uid_subpacket);

	if (result == NULL)
	{
		pgp_user_attribute_packet_delete(packet);
		return NULL;
	}

	packet->subpackets = result;
	packet->subpacket_octets += PGP_SUBPACKET_OCTETS(uid_subpacket->header);

	pgp_user_attribute_encode_header(packet);

	return packet;
}

static pgp_error_t pgp_user_attribute_packet_read_body(pgp_user_attribute_packet *packet, buffer_t *buffer)
{
	pgp_error_t error = 0;

	while (buffer->pos < buffer->size)
	{
		void *subpacket = NULL;
		void *result = NULL;

		error = pgp_user_attribute_subpacket_read(&subpacket, buffer);

		if (error != PGP_SUCCESS)
		{
			return error;
		}

		result = pgp_stream_push_packet(packet->subpackets, subpacket);

		if (result == NULL)
		{
			return PGP_NO_MEMORY;
		}

		packet->subpackets = result;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_user_attribute_packet_read_with_header(pgp_user_attribute_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_user_attribute_packet *uat = NULL;

	uat = malloc(sizeof(pgp_user_attribute_packet));

	if (uat == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(uat, 0, sizeof(pgp_user_attribute_packet));

	uat->subpackets = pgp_stream_new(4);

	if (uat->subpackets == NULL)
	{
		pgp_user_attribute_packet_delete(uat);
		return PGP_NO_MEMORY;
	}

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	uat->header = *header;

	// Read the body
	error = pgp_user_attribute_packet_read_body(uat, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_user_attribute_packet_delete(uat);
		return error;
	}

	*packet = uat;

	return error;
}

pgp_error_t pgp_user_attribute_packet_read(pgp_user_attribute_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_UAT)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_user_attribute_packet_read_with_header(packet, &header, data);
}

size_t pgp_user_attribute_packet_write(pgp_user_attribute_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Subpackets
	for (uint16_t i = 0; i < packet->subpackets->count; ++i)
	{
		pos += pgp_user_attribute_subpacket_write(packet->subpackets->packets[i], out + pos, size - pos);
	}

	return pos;
}

pgp_error_t pgp_padding_packet_new(pgp_padding_packet **packet, void *data, uint32_t size)
{
	pgp_padding_packet *padding = NULL;
	uint32_t required_size = sizeof(pgp_packet_header) + size;

	if (size == 0)
	{
		return PGP_EMPTY_PADDING_PACKET;
	}

	padding = malloc(required_size);

	if (padding == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(padding, 0, required_size);

	if (data != NULL)
	{
		memcpy(padding->data, data, size);
	}
	else
	{
		// Generate random data
		// Only consider the error case if we output no padding data.
		size = pgp_rand(padding->data, size);

		if (size == 0)
		{
			pgp_padding_packet_delete(padding);
			return PGP_RAND_ERROR;
		}
	}

	// N octets of padding data
	padding->header = pgp_encode_packet_header(PGP_HEADER, PGP_PADDING, size);

	*packet = padding;

	return PGP_SUCCESS;
}

void pgp_padding_packet_delete(pgp_padding_packet *packet)
{
	free(packet);
}

pgp_error_t pgp_padding_packet_read_with_header(pgp_padding_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_padding_packet *padding = NULL;

	padding = malloc(sizeof(pgp_padding_packet) + header->body_size);

	if (padding == NULL)
	{
		return PGP_NO_MEMORY;
	}

	// Copy the header
	padding->header = *header;

	// Copy the padding data.
	memcpy(padding->data, PTR_OFFSET(data, header->header_size), header->body_size);

	*packet = padding;

	return PGP_SUCCESS;
}

pgp_error_t pgp_padding_packet_read(pgp_padding_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_PADDING)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_padding_packet_read_with_header(packet, &header, data);
}

size_t pgp_padding_packet_write(pgp_padding_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
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

pgp_error_t pgp_mdc_packet_new(pgp_mdc_packet **packet, byte_t hash[20])
{
	pgp_mdc_packet *mdc = malloc(sizeof(pgp_mdc_packet));

	if (mdc == NULL)
	{
		return PGP_NO_MEMORY;
	}

	// 20 octets of SHA-1 hash
	memset(mdc, 0, sizeof(pgp_mdc_packet));
	memcpy(mdc->sha1_hash, hash, 20);

	mdc->header = pgp_encode_packet_header(PGP_HEADER, PGP_MDC, 20);

	*packet = mdc;

	return PGP_SUCCESS;
}

void pgp_mdc_packet_delete(pgp_mdc_packet *packet)
{
	free(packet);
}

pgp_error_t pgp_mdc_packet_read_with_header(pgp_mdc_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_mdc_packet *mdc = NULL;

	// The body size should be the length of the SHA-1 hash size
	if (header->body_size != 20)
	{
		return PGP_MALFORMED_MDC_PACKET;
	}

	mdc = malloc(sizeof(pgp_mdc_packet));

	if (mdc == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(mdc, 0, sizeof(pgp_mdc_packet));

	// Copy the header
	mdc->header = *header;

	// Copy the SHA-1 hash
	memcpy(mdc->sha1_hash, PTR_OFFSET(data, header->header_size), 20);

	*packet = mdc;

	return PGP_SUCCESS;
}

pgp_error_t pgp_mdc_packet_read(pgp_mdc_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_MDC)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	return pgp_mdc_packet_read_with_header(packet, &header, data);
}

size_t pgp_mdc_packet_write(pgp_mdc_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
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

pgp_error_t pgp_trust_packet_new(pgp_trust_packet **packet, byte_t header_format, byte_t trust_level)
{
	pgp_trust_packet *trust = NULL;

	if (header_format != PGP_HEADER && header_format != PGP_LEGACY_HEADER)
	{
		return PGP_INVALID_HEADER_FORMAT;
	}

	if (trust_level != PGP_TRUST_NEVER && trust_level != PGP_TRUST_MARGINAL && trust_level != PGP_TRUST_FULL &&
		trust_level != PGP_TRUST_ULTIMATE)
	{
		return PGP_INVALID_TRUST_LEVEL;
	}

	trust = malloc(sizeof(pgp_trust_packet));

	if (trust == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(trust, 0, sizeof(pgp_trust_packet));
	trust->header = pgp_encode_packet_header(header_format, PGP_TRUST, 1);
	trust->level = trust_level;

	*packet = trust;

	return PGP_SUCCESS;
}

void pgp_trust_packet_delete(pgp_trust_packet *packet)
{
	free(packet);
}

pgp_error_t pgp_trust_packet_read_with_header(pgp_trust_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_trust_packet *trust = NULL;

	// Body should only contain 1 octet of trust level
	if (header->body_size != 1)
	{
		return PGP_MALFORMED_TRUST_PACKET;
	}

	trust = malloc(sizeof(pgp_trust_packet));

	if (trust == NULL)
	{
		return PGP_SUCCESS;
	}

	// Copy the header
	trust->header = *header;

	// 1 octet trust level
	LOAD_8(&trust->level, PTR_OFFSET(data, header->header_size));

	*packet = trust;

	return PGP_SUCCESS;
}

pgp_error_t pgp_trust_packet_read(pgp_trust_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_TRUST)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	return pgp_trust_packet_read_with_header(packet, &header, data);
}

size_t pgp_trust_packet_write(pgp_trust_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet trust level
	LOAD_8(out + pos, &packet->level);
	pos += 1;

	return pos;
}

static void pgp_keyring_packet_encode_header(pgp_keyring_packet *packet)
{
	uint32_t body_size = 0;

	// A 1-octet key version.
	// A 1-octet trust level.
	// N octets of primary key fingerprint.
	// A 4-octet subkey fingerprint size.
	// N octets of subkey fingerprints.
	// A 4-octet uid size.
	// N octets of uid data.

	body_size = 1 + 1 + 4 + 4 + packet->fingerprint_size + packet->subkey_size + packet->uid_size;
	packet->header = pgp_encode_packet_header(PGP_HEADER, PGP_KEYRING, body_size);
}

pgp_error_t pgp_keyring_packet_new(pgp_keyring_packet **packet, byte_t key_version, byte_t trust_level, byte_t primary_key[32], byte_t *uid,
								   uint32_t uid_size)
{
	pgp_keyring_packet *keyring = NULL;

	if (key_version < PGP_KEY_V2 || key_version > PGP_KEY_V6)
	{
		return PGP_INVALID_KEY_VERSION;
	}

	if (uid == NULL || uid_size == 0)
	{
		return PGP_EMPTY_USER_ID;
	}

	if (trust_level != PGP_TRUST_NEVER && trust_level != PGP_TRUST_MARGINAL && trust_level != PGP_TRUST_FULL &&
		trust_level != PGP_TRUST_ULTIMATE)
	{
		return PGP_INVALID_TRUST_LEVEL;
	}

	keyring = malloc(sizeof(pgp_keyring_packet));

	if (keyring == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(keyring, 0, sizeof(pgp_keyring_packet));

	keyring->key_version = key_version;
	keyring->trust_level = trust_level;

	keyring->fingerprint_size = pgp_key_fingerprint_size(key_version);
	memcpy(keyring->primary_fingerprint, primary_key, keyring->fingerprint_size);

	keyring->uids = malloc(uid_size + 1);

	if (keyring == NULL)
	{
		pgp_keyring_packet_delete(keyring);
		return PGP_NO_MEMORY;
	}

	memset(keyring->uids, 0, uid_size + 1);

	memcpy(keyring->uids, uid, uid_size);
	keyring->uid_count = 1;
	keyring->uid_size = keyring->uid_capacity = uid_size + 1;

	pgp_keyring_packet_encode_header(keyring);

	*packet = keyring;

	return PGP_SUCCESS;
}

void pgp_keyring_packet_delete(pgp_keyring_packet *packet)
{
	free(packet->subkey_fingerprints);
	free(packet->uids);

	free(packet);
}

pgp_error_t pgp_keyring_packet_add_uid(pgp_keyring_packet *packet, byte_t *uid, uint32_t uid_size)
{
	if ((packet->uid_capacity - packet->uid_size) < (uid_size + 1))
	{
		void *temp = NULL;

		packet->uid_capacity = MAX(packet->subkey_capacity * 2, packet->uid_size + uid_size + 1);
		temp = realloc(packet->uids, packet->uid_capacity);

		if (temp == NULL)
		{
			return PGP_NO_MEMORY;
		}

		packet->uids = temp;

		memset(PTR_OFFSET(packet->uids, packet->uid_size), 0, packet->uid_capacity - packet->uid_size);
	}

	memcpy(PTR_OFFSET(packet->uids, packet->uid_size), uid, uid_size);
	packet->uid_size += uid_size + 1;
	packet->uid_count += 1;

	pgp_keyring_packet_encode_header(packet);

	return PGP_SUCCESS;
}

void pgp_keyring_packet_remove_uid(pgp_keyring_packet *packet, byte_t *uid, uint32_t uid_size)
{
	void *start = packet->uids;
	void *end = PTR_OFFSET(packet->uids, packet->uid_size);
	void *ptr = start;

	while (ptr != end)
	{
		ptr = memchr(ptr, 0, packet->uid_size - (uint32_t)((uintptr_t)end - (uintptr_t)ptr));

		if (ptr == NULL)
		{
			ptr = PTR_OFFSET(end, -1);
		}

		if (memcmp(start, uid, uid_size) == 0)
		{
			ptr = PTR_OFFSET(ptr, 1);

			memmove(start, ptr, (uintptr_t)end - (uintptr_t)ptr);

			packet->uid_size -= uid_size + 1;
			packet->uid_count -= 1;

			memset(PTR_OFFSET(packet->uids, packet->uid_size), 0, packet->uid_capacity - packet->uid_size);

			break;
		}

		start = ptr;
	}

	pgp_keyring_packet_encode_header(packet);
}

pgp_error_t pgp_keyring_packet_add_subkey(pgp_keyring_packet *packet, byte_t subkey[32])
{
	if ((packet->subkey_capacity - packet->subkey_size) < packet->fingerprint_size)
	{
		if (packet->subkey_fingerprints == NULL)
		{
			packet->subkey_fingerprints = malloc(packet->fingerprint_size);

			if (packet->subkey_fingerprints == NULL)
			{
				return PGP_NO_MEMORY;
			}

			packet->subkey_capacity = packet->fingerprint_size;
		}
		else
		{
			void *temp = NULL;

			packet->subkey_capacity *= 2;
			temp = realloc(packet->subkey_fingerprints, packet->subkey_capacity);

			if (temp == NULL)
			{
				return PGP_NO_MEMORY;
			}

			packet->subkey_fingerprints = temp;
		}
	}

	memcpy(PTR_OFFSET(packet->subkey_fingerprints, packet->subkey_size), subkey, packet->fingerprint_size);
	packet->subkey_size += packet->fingerprint_size;
	packet->subkey_count += 1;

	pgp_keyring_packet_encode_header(packet);

	return PGP_SUCCESS;
}

void pgp_keyring_packet_remove_subkey(pgp_keyring_packet *packet, byte_t subkey[32])
{
	// Find the subkey
	for (byte_t i = 0; i < packet->subkey_count; ++i)
	{
		if (memcmp(PTR_OFFSET(packet->subkey_fingerprints, i * packet->fingerprint_size), subkey, packet->fingerprint_size) == 0)
		{
			memmove(PTR_OFFSET(packet->subkey_fingerprints, i * packet->fingerprint_size),
					PTR_OFFSET(packet->subkey_fingerprints, (i + 1) * packet->fingerprint_size),
					(packet->subkey_count - (i + 1)) * packet->fingerprint_size);
			memset(PTR_OFFSET(packet->subkey_fingerprints, (packet->subkey_count - 1) * packet->fingerprint_size), 0,
				   packet->fingerprint_size);

			packet->subkey_size -= packet->fingerprint_size;
			packet->subkey_count -= 1;

			break;
		}
	}

	pgp_keyring_packet_encode_header(packet);
}

static pgp_error_t pgp_keyring_packet_read_body(pgp_keyring_packet *packet, buffer_t *buffer)
{
	//  A 1-octet key version
	CHECK_READ(read8(buffer, &packet->key_version), PGP_MALFORMED_KEYRING_PACKET);

	// This is a private packet, catch any invalid values here.
	if (packet->key_version < PGP_KEY_V2 || packet->key_version > PGP_KEY_V6)
	{
		return PGP_INVALID_KEY_VERSION;
	}

	//  A 1-octet trust level
	CHECK_READ(read8(buffer, &packet->trust_level), PGP_MALFORMED_KEYRING_PACKET);

	if (packet->trust_level != PGP_TRUST_NEVER && packet->trust_level != PGP_TRUST_MARGINAL && packet->trust_level != PGP_TRUST_FULL &&
		packet->trust_level != PGP_TRUST_ULTIMATE)
	{
		return PGP_INVALID_TRUST_LEVEL;
	}

	packet->fingerprint_size = pgp_key_fingerprint_size(packet->key_version);

	// N octets of primary key fingerprint
	CHECK_READ(readn(buffer, packet->primary_fingerprint, packet->fingerprint_size), PGP_MALFORMED_KEYRING_PRIMARY_KEY);

	// A 4-octet subkey fingerprint size
	CHECK_READ(read32_be(buffer, &packet->subkey_size), PGP_MALFORMED_KEYRING_PACKET);

	if (packet->subkey_size % packet->fingerprint_size != 0)
	{
		return PGP_KEYRING_PACKET_INVALID_SUBKEY_SIZE;
	}

	// N octets of subkey fingerprints.
	packet->subkey_fingerprints = malloc(packet->subkey_size);

	if (packet->subkey_fingerprints == NULL)
	{
		return PGP_NO_MEMORY;
	}

	packet->subkey_capacity = packet->subkey_size;
	packet->subkey_count = packet->subkey_size / packet->fingerprint_size;

	CHECK_READ(readn(buffer, packet->subkey_fingerprints, packet->subkey_size), PGP_MALFORMED_KEYRING_SUBKEYS);

	// A 4-octet uid size
	CHECK_READ(read32_be(buffer, &packet->uid_size), PGP_MALFORMED_KEYRING_PACKET);

	if (packet->uid_size == 0)
	{
		return PGP_EMPTY_USER_ID;
	}

	packet->uids = malloc(packet->uid_size);

	if (packet->uids == NULL)
	{
		return PGP_NO_MEMORY;
	}

	packet->uid_capacity = packet->uid_size;

	CHECK_READ(readn(buffer, packet->uids, packet->uid_size), PGP_KEYRING_PACKET_INVALID_UID_SIZE);

	// Count the UIDs
	// Each UID is delimited by a NULL (including the last one).
	void *start = packet->uids;
	void *end = PTR_OFFSET(packet->uids, packet->uid_size);
	void *ptr = start;

	while (ptr != end)
	{
		ptr = memchr(ptr, 0, packet->uid_size - (uint32_t)((uintptr_t)end - (uintptr_t)ptr));

		if (ptr == NULL)
		{
			packet->uid_count += 1;
			break;
		}

		ptr = PTR_OFFSET(ptr, 1);
		packet->uid_count += 1;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_keyring_packet_read_with_header(pgp_keyring_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_keyring_packet *keyring = NULL;

	keyring = malloc(sizeof(pgp_keyring_packet));

	if (keyring == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(keyring, 0, sizeof(pgp_keyring_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	keyring->header = *header;

	// Read the body
	error = pgp_keyring_packet_read_body(keyring, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_keyring_packet_delete(keyring);
		return error;
	}

	*packet = keyring;

	return error;
}

pgp_error_t pgp_keyring_packet_read(pgp_keyring_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_KEYRING)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_keyring_packet_read_with_header(packet, &header, data);
}

size_t pgp_keyring_packet_write(pgp_keyring_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	//  A 1-octet key version
	LOAD_8(out + pos, &packet->key_version);
	pos += 1;

	//  A 1-octet trust level
	LOAD_8(out + pos, &packet->trust_level);
	pos += 1;

	// N octets of primary key fingerprint
	memcpy(out + pos, packet->primary_fingerprint, packet->fingerprint_size);
	pos += packet->fingerprint_size;

	// A 4-octet subkey fingerprint size
	uint32_t subkey_size_be = BSWAP_32(packet->subkey_size);
	LOAD_32(out + pos, &subkey_size_be);
	pos += 4;

	// N octets of subkey fingerprints.
	memcpy(out + pos, packet->subkey_fingerprints, packet->subkey_size);
	pos += packet->subkey_size;

	// A 4-octet uid size
	uint32_t uid_size_be = BSWAP_32(packet->uid_size);
	LOAD_32(out + pos, &uid_size_be);
	pos += 4;

	memcpy(out + pos, packet->uids, packet->uid_size);
	pos += packet->uid_size;

	return pos;
}

pgp_error_t pgp_unknown_packet_read_with_header(pgp_unknown_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_unknown_packet *unknown = NULL;

	unknown = malloc(sizeof(pgp_unknown_packet) + header->body_size);

	if (unknown == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(unknown, 0, sizeof(pgp_unknown_packet) + header->body_size);

	unknown->data = PTR_OFFSET(unknown, sizeof(pgp_unknown_packet));

	// Copy the header
	unknown->header = *header;

	// Copy the data.
	memcpy(unknown->data, PTR_OFFSET(data, header->header_size), header->body_size);

	*packet = unknown;

	return PGP_SUCCESS;
}

pgp_error_t pgp_unknown_packet_read(pgp_unknown_packet **packet, void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	return pgp_unknown_packet_read_with_header(packet, &header, data);
}

size_t pgp_unknown_packet_write(pgp_unknown_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Data
	memcpy(out + pos, packet->data, packet->header.body_size);
	pos += packet->header.body_size;

	return pos;
}
