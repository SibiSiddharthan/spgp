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

static size_t pgp_stream_write_internal(pgp_stream_t *stream, void *buffer, size_t size)
{
	size_t pos = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		pos += pgp_packet_write(stream->packets[i], PTR_OFFSET(buffer, pos), size - pos);
	}

	return pos;
}

static void pgp_compressed_packet_encode_header(pgp_compresed_packet *packet, pgp_packet_header_format header_format, byte_t partial)
{
	size_t body_size = 0;

	if (header_format == 0)
	{
		header_format = PGP_PACKET_HEADER_FORMAT(packet->header.tag);
	}

	// 1 octet of compression algorithm
	// N bytes of compressed data

	body_size = 1 + packet->data_size;

	if (body_size > ((uint64_t)1 << 32))
	{
		partial = 1;
		header_format = PGP_LEGACY_HEADER;
	}

	packet->header = pgp_packet_header_encode(header_format, PGP_COMP, partial, body_size);
}

pgp_error_t pgp_compressed_packet_new(pgp_compresed_packet **packet, byte_t header_format, byte_t compression_algorithm_id)
{
	pgp_compresed_packet *compressed = NULL;

	if (header_format != PGP_HEADER && header_format != PGP_LEGACY_HEADER)
	{
		return PGP_UNKNOWN_HEADER_FORMAT;
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
	pgp_compressed_packet_encode_header(compressed, header_format, 0);

	*packet = compressed;

	return PGP_SUCCESS;
}

void pgp_compressed_packet_delete(pgp_compresed_packet *packet)
{
	free(packet->data);
	free(packet);
}

pgp_error_t pgp_compressed_packet_compress(pgp_compresed_packet *packet, pgp_stream_t *stream)
{

	switch (packet->compression_algorithm_id)
	{
	case PGP_UNCOMPRESSED:
	{
		size_t data_size = pgp_packet_stream_octets(stream);

		packet->data_size = data_size;
		packet->data = malloc(data_size);

		if (packet->data == NULL)
		{
			return PGP_NO_MEMORY;
		}

		pgp_stream_write_internal(stream, packet->data, data_size);

		// Set the header
		pgp_compressed_packet_encode_header(packet, 0, 0);

		return PGP_SUCCESS;
	}
	case PGP_DEFALTE:
	case PGP_ZLIB:
	case PGP_BZIP2:
		// TODO: Implement compression
	default:
		return PGP_UNSUPPORTED_COMPRESSION_ALGORITHM;
	}
}

pgp_error_t pgp_compressed_packet_decompress(pgp_compresed_packet *packet, pgp_stream_t **stream)
{
	pgp_error_t status = 0;
	pgp_packet_header *header = NULL;

	switch (packet->compression_algorithm_id)
	{
	case PGP_UNCOMPRESSED:
	{
		status = pgp_packet_stream_read(stream, packet->data, packet->data_size);

		if (status != PGP_SUCCESS)
		{
			return status;
		}
	}
	case PGP_DEFALTE:
	case PGP_ZLIB:
	case PGP_BZIP2:
		// TODO: Implement compression
	default:
		return PGP_UNSUPPORTED_COMPRESSION_ALGORITHM;
	}

	// Check for recursive compression
	for (uint32_t i = 0; i < (*stream)->count; ++i)
	{
		header = (*stream)->packets[i];

		if (pgp_packet_type_from_tag(header->tag) == PGP_COMP)
		{
			return PGP_RECURSIVE_COMPRESSION_CONTAINER;
		}
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_compressed_packet_collate(pgp_compresed_packet *packet)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_collate((pgp_data_packet *)packet);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	pgp_compressed_packet_encode_header(packet, 0, 0);

	return PGP_SUCCESS;
}

pgp_error_t pgp_compressed_packet_split(pgp_compresed_packet *packet, byte_t split)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_split((pgp_data_packet *)packet, split);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	pgp_compressed_packet_encode_header(packet, PGP_HEADER, 1);

	return PGP_SUCCESS;
}

static pgp_error_t pgp_compressed_packet_read_body(pgp_compresed_packet *packet, buffer_t *buffer)
{
	packet->data_size = packet->header.body_size - 1;

	// 1 octet compression algorithm
	CHECK_READ(read8(buffer, &packet->compression_algorithm_id), PGP_MALFORMED_COMPRESSED_PACKET);

	// Copy the compressed data.
	if (packet->data_size > 0)
	{
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			return PGP_NO_MEMORY;
		}

		readn(buffer, packet->data, packet->data_size);
	}

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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_COMP)
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

	size_t required_size = 0;

	required_size = PGP_PACKET_OCTETS(packet->header);

	if (packet->partials != NULL)
	{
		required_size += pgp_packet_stream_octets(packet->partials);
	}

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
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	if (packet->partials != NULL)
	{
		// The last partial packet will contain the tag
		for (uint32_t i = 0; i < packet->partials->count; ++i)
		{
			pos += pgp_partial_packet_write(packet->partials->packets[i], out + pos, size - pos);
		}
	}

	return pos;
}

pgp_error_t pgp_marker_packet_new(pgp_marker_packet **packet, byte_t header_format)
{
	pgp_marker_packet *marker = NULL;

	if (header_format != PGP_HEADER && header_format != PGP_LEGACY_HEADER)
	{
		return PGP_UNKNOWN_HEADER_FORMAT;
	}

	marker = malloc(sizeof(pgp_marker_packet));

	if (marker == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(packet, 0, sizeof(pgp_marker_packet));

	// 3 octets of marker
	marker->header = pgp_packet_header_encode(header_format, PGP_MARKER, 0, 3);

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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_MARKER)
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

	// Marker data
	memcpy(out + pos, packet->marker, 3);
	pos += 3;

	return pos;
}

static void pgp_literal_packet_encode_header(pgp_literal_packet *packet, pgp_packet_header_format header_format, byte_t partial)
{
	size_t body_size = 0;

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

	if (body_size > ((uint64_t)1 << 32))
	{
		partial = 1;
		header_format = PGP_LEGACY_HEADER;
	}

	packet->header = pgp_packet_header_encode(header_format, PGP_LIT, partial, body_size);
}

pgp_error_t pgp_literal_packet_new(pgp_literal_packet **packet, byte_t header_format, uint32_t date, void *filename, byte_t filename_size)
{
	pgp_literal_packet *literal = NULL;

	if (header_format != PGP_HEADER && header_format != PGP_LEGACY_HEADER)
	{
		return PGP_UNKNOWN_HEADER_FORMAT;
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

	pgp_literal_packet_encode_header(literal, header_format, 0);

	*packet = literal;

	return PGP_SUCCESS;
}

void pgp_literal_packet_delete(pgp_literal_packet *packet)
{
	if (packet == NULL)
	{
		return;
	}

	free(packet->filename);
	free(packet->data);
	free(packet);
}

pgp_error_t pgp_literal_packet_retrieve(pgp_literal_packet *packet, void *data, size_t size)
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

pgp_error_t pgp_literal_packet_store(pgp_literal_packet *packet, pgp_literal_data_format format, void *data, size_t size)
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

	pgp_literal_packet_encode_header(packet, 0, 0);

	return PGP_SUCCESS;
}

pgp_error_t pgp_literal_packet_collate(pgp_literal_packet *packet)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_collate((pgp_data_packet *)packet);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	pgp_literal_packet_encode_header(packet, 0, 0);

	return PGP_SUCCESS;
}

pgp_error_t pgp_literal_packet_split(pgp_literal_packet *packet, byte_t split)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_split((pgp_data_packet *)packet, split);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	pgp_literal_packet_encode_header(packet, PGP_HEADER, 1);

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

		CHECK_READ(readn(buffer, packet->filename, packet->filename_size), PGP_MALFORMED_LITERAL_PACKET_FILENAME_SIZE);
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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_LIT)
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

	size_t required_size = 0;

	required_size = PGP_PACKET_OCTETS(packet->header);

	if (packet->partials != NULL)
	{
		required_size += pgp_packet_stream_octets(packet->partials);
	}

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
	LOAD_32BE(out + pos, &packet->date);
	pos += 4;

	// Literal data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	if (packet->partials != NULL)
	{
		// The last partial packet will contain the tag
		for (uint32_t i = 0; i < packet->partials->count; ++i)
		{
			pos += pgp_partial_packet_write(packet->partials->packets[i], out + pos, size - pos);
		}
	}

	return pos;
}

uint32_t pgp_user_id_generate(void *buffer, uint32_t size, void *user_name, uint16_t user_name_size, void *user_comment,
							  uint16_t user_comment_size, void *user_email, uint16_t user_email_size)
{
	byte_t *out = buffer;
	uint32_t pos = 0;
	uint32_t required_size = user_name_size + user_comment_size + user_email_size;

	if (required_size == 0)
	{
		return 0;
	}

	if (user_comment_size > 0)
	{
		required_size += 3; // '(' and ')' and ' '
	}

	if (user_email_size > 0)
	{
		required_size += 3; // '<' and '>' and ' '
	}

	if (size < required_size)
	{
		return 0;
	}

	// Data is stored as "user_name (user_comment) <user_email>"
	memcpy(out + pos, user_name, user_name_size);
	pos += user_name_size;

	if (user_comment_size > 0)
	{
		out[pos++] = ' ';
		out[pos++] = '(';

		memcpy(out + pos, user_comment, user_comment_size);
		pos += user_comment_size;

		out[pos++] = '(';
	}

	if (user_email_size > 0)
	{
		out[pos++] = ' ';
		out[pos++] = '<';

		memcpy(out + pos, user_email, user_email_size);
		pos += user_email_size;

		out[pos++] = '>';
	}

	return required_size;
}

pgp_error_t pgp_user_id_packet_new(pgp_user_id_packet **packet, byte_t header_format, void *user, uint16_t user_size)
{
	pgp_user_id_packet *uid = NULL;
	size_t required_size = sizeof(pgp_packet_header) + user_size;

	if (header_format != PGP_HEADER && header_format != PGP_LEGACY_HEADER)
	{
		return PGP_UNKNOWN_HEADER_FORMAT;
	}

	if (user_size == 0)
	{
		return PGP_EMPTY_USER_ID;
	}

	uid = malloc(required_size);

	if (uid == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(uid, 0, required_size);

	// N octets of user data
	memcpy(uid->user_data, user, user_size);
	uid->header = pgp_packet_header_encode(header_format, PGP_UID, 0, user_size);

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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_UID)
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
	pgp_error_t error = 0;
	pgp_subpacket_header header = {0};

	error = pgp_subpacket_header_read(&header, buffer->data + buffer->pos, buffer->size - buffer->pos);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (header.tag == 0)
	{
		return PGP_UNKNOWN_USER_ATTRIBUTE_SUBPACKET_TAG;
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
		readn(buffer, image_subpacket->image_data, image_size);

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
		readn(buffer, uid_subpacket->user_data, uid_size);

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
		readn(buffer, unknown->data, header.body_size);

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

static void pgp_user_attribute_subpacket_delete(void *subpacket)
{
	free(subpacket);
}

static void pgp_user_attribute_encode_header(pgp_user_attribute_packet *packet)
{
	// N octets of subpackets
	packet->header = pgp_packet_header_encode(PGP_HEADER, PGP_UAT, 0, packet->subpacket_octets);
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
	pgp_stream_delete(packet->subpackets, pgp_user_attribute_subpacket_delete);
	free(packet);
}

pgp_error_t pgp_user_attribute_packet_get_image(pgp_user_attribute_packet *packet, void *image, size_t *size)
{
	pgp_subpacket_header *subpacket_header = NULL;

	if (packet->subpackets == NULL)
	{
		return PGP_IMAGE_NOT_PRESENT_IN_USER_ATTRIBUTE;
	}

	for (uint32_t i = 0; i < packet->subpackets->count; ++i)
	{
		subpacket_header = packet->subpackets->packets[i];

		// Return the image data of the first image subpacket.
		if ((subpacket_header->tag & PGP_SUBPACKET_TAG_MASK) == PGP_USER_ATTRIBUTE_IMAGE)
		{
			pgp_user_attribute_image_subpacket *image_subpacket = packet->subpackets->packets[i];
			uint32_t image_size = image_subpacket->header.body_size - 16;

			if (*size < image_size)
			{
				return PGP_BUFFER_TOO_SMALL;
			}

			memcpy(image, image_subpacket->image_data, image_size);
			*size = image_size;

			return PGP_SUCCESS;
		}
	}

	return PGP_IMAGE_NOT_PRESENT_IN_USER_ATTRIBUTE;
}

pgp_error_t pgp_user_attribute_packet_set_image(pgp_user_attribute_packet *packet, byte_t format, void *image, size_t size)
{
	void *result = NULL;

	pgp_user_attribute_image_subpacket *image_subpacket = NULL;
	size_t required_size = sizeof(pgp_user_attribute_image_subpacket) + size;

	if (format != PGP_USER_ATTRIBUTE_IMAGE_JPEG)
	{
		return PGP_UNSUPPORTED_IMAGE_TYPE;
	}

	// Set the image data
	image_subpacket = malloc(required_size);

	if (image_subpacket == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(image_subpacket, 0, required_size);

	image_subpacket->image_header_size = 1;
	image_subpacket->image_header_version = 1;
	image_subpacket->image_encoding = format;
	memcpy(image_subpacket->image_data, image, size);

	image_subpacket->header = pgp_subpacket_header_encode(PGP_USER_ATTRIBUTE_IMAGE, 0, 16 + size);

	result = pgp_stream_push(packet->subpackets, image_subpacket);

	if (result == NULL)
	{
		pgp_user_attribute_packet_delete(packet);
		return PGP_NO_MEMORY;
	}

	packet->subpackets = result;
	packet->subpacket_octets += PGP_SUBPACKET_OCTETS(image_subpacket->header);

	pgp_user_attribute_encode_header(packet);

	return PGP_SUCCESS;
}

pgp_error_t pgp_user_attribute_packet_get_uid(pgp_user_attribute_packet *packet, void *data, size_t *size)
{
	pgp_subpacket_header *subpacket_header = NULL;

	if (packet->subpackets == NULL)
	{
		return PGP_ID_NOT_PRESENT_IN_USER_ATTRIBUTE;
	}

	for (uint32_t i = 0; i < packet->subpackets->count; ++i)
	{
		subpacket_header = packet->subpackets->packets[i];

		// Return the image data of the first image subpacket.
		if ((subpacket_header->tag & PGP_SUBPACKET_TAG_MASK) == PGP_USER_ATTRIBUTE_UID)
		{
			pgp_user_attribute_uid_subpacket *uid_subpacket = packet->subpackets->packets[i];
			uint32_t uid_size = uid_subpacket->header.body_size;

			if (*size < uid_size)
			{
				return PGP_BUFFER_TOO_SMALL;
			}

			memcpy(data, uid_subpacket->user_data, uid_size);
			*size = uid_size;

			return PGP_SUCCESS;
		}
	}

	return PGP_ID_NOT_PRESENT_IN_USER_ATTRIBUTE;
}

pgp_error_t pgp_user_attribute_packet_set_uid(pgp_user_attribute_packet *packet, void *user, size_t size)
{
	void *result = NULL;

	pgp_error_t status = 0;
	pgp_user_attribute_uid_subpacket *uid_subpacket = NULL;
	pgp_user_id_packet *uid_packet = NULL;

	status = pgp_user_id_packet_new(&uid_packet, PGP_HEADER, user, size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Layout is the same. Just change the tag.
	uid_subpacket = (pgp_user_attribute_uid_subpacket *)uid_packet;
	uid_subpacket->header.tag = PGP_USER_ATTRIBUTE_UID;

	result = pgp_stream_push(packet->subpackets, uid_subpacket);

	if (result == NULL)
	{
		pgp_user_attribute_packet_delete(packet);
		return PGP_NO_MEMORY;
	}

	packet->subpackets = result;
	packet->subpacket_octets += PGP_SUBPACKET_OCTETS(uid_subpacket->header);

	pgp_user_attribute_encode_header(packet);

	return PGP_SUCCESS;
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

		result = pgp_stream_push(packet->subpackets, subpacket);

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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_UAT)
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
	for (uint32_t i = 0; i < packet->subpackets->count; ++i)
	{
		pos += pgp_user_attribute_subpacket_write(packet->subpackets->packets[i], out + pos, size - pos);
	}

	return pos;
}

pgp_error_t pgp_padding_packet_new(pgp_padding_packet **packet, void *data, uint32_t size)
{
	pgp_error_t status = 0;

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
		status = pgp_rand(padding->data, size);

		if (status != PGP_SUCCESS)
		{
			return status;
		}
	}

	// N octets of padding data
	padding->header = pgp_packet_header_encode(PGP_HEADER, PGP_PADDING, 0, size);

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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_PADDING)
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

	mdc->header = pgp_packet_header_encode(PGP_HEADER, PGP_MDC, 0, 20);

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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_MDC)
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
		return PGP_UNKNOWN_HEADER_FORMAT;
	}

	if (trust_level != PGP_TRUST_NEVER && trust_level != PGP_TRUST_REVOKED && trust_level != PGP_TRUST_MARGINAL &&
		trust_level != PGP_TRUST_FULL && trust_level != PGP_TRUST_ULTIMATE)
	{
		return PGP_UNKNOWN_TRUST_LEVEL;
	}

	trust = malloc(sizeof(pgp_trust_packet));

	if (trust == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(trust, 0, sizeof(pgp_trust_packet));
	trust->header = pgp_packet_header_encode(header_format, PGP_TRUST, 0, 1);
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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_TRUST)
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
	// N octets of primary key fingerprint.
	// A 4-octet subkey fingerprint size.
	// N octets of subkey fingerprints.
	// A 4-octet user size.
	// N octets of user data.

	body_size = 1 + 4 + 4 + packet->fingerprint_size + packet->subkey_size + packet->user_size;
	packet->header = pgp_packet_header_encode(PGP_HEADER, PGP_KEYRING, 0, body_size);
}

pgp_error_t pgp_keyring_packet_new(pgp_keyring_packet **packet, byte_t key_version,
								   byte_t primary_key_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], pgp_user_info *user)
{
	pgp_error_t status = 0;
	pgp_keyring_packet *keyring = NULL;

	if (key_version < PGP_KEY_V2 || key_version > PGP_KEY_V6)
	{
		return PGP_UNKNOWN_KEY_VERSION;
	}

	keyring = malloc(sizeof(pgp_keyring_packet));

	if (keyring == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(keyring, 0, sizeof(pgp_keyring_packet));

	// Copy the key information
	keyring->key_version = key_version;

	keyring->fingerprint_size = pgp_key_fingerprint_size(key_version);
	memcpy(keyring->primary_fingerprint, primary_key_fingerprint, keyring->fingerprint_size);

	// Add the user information (will also encode the header)
	if (user != NULL)
	{
		status = pgp_keyring_packet_add_user(keyring, user);

		if (status != PGP_SUCCESS)
		{
			pgp_keyring_packet_delete(keyring);
			return status;
		}
	}

	*packet = keyring;

	return PGP_SUCCESS;
}

void pgp_keyring_packet_delete(pgp_keyring_packet *packet)
{
	if (packet == NULL)
	{
		return;
	}

	pgp_stream_delete(packet->users, (void (*)(void *))pgp_user_info_delete);
	free(packet->subkey_fingerprints);

	free(packet);
}

pgp_error_t pgp_keyring_packet_add_user(pgp_keyring_packet *packet, pgp_user_info *user)
{
	void *result = NULL;

	result = pgp_stream_push(packet->users, user);

	if (result == NULL)
	{
		return PGP_NO_MEMORY;
	}

	packet->users = result;
	packet->user_size = user->info_octets + 4;

	pgp_keyring_packet_encode_header(packet);

	return PGP_SUCCESS;
}

void pgp_keyring_packet_remove_user(pgp_keyring_packet *packet, byte_t *uid, uint32_t uid_size)
{
	pgp_user_info *user = NULL;

	for (uint32_t i = 0; i < packet->users->count; ++i)
	{
		user = packet->users->packets[i];

		if (user->uid != NULL)
		{
			if ((user->uid_octets == uid_size) && (memcmp(user->uid, uid, uid_size) == 0))
			{
				// Shift the pointers
				for (uint32_t j = i; j < packet->users->count - 1; ++j)
				{
					packet->users[j] = packet->users[j + 1];
				}

				packet->users->packets[packet->users->count - 1] = NULL;
				packet->users->count -= 1;
				packet->user_size -= user->info_octets + 4;

				// Delete the user info.
				free(user);

				break;
			}
		}
	}

	pgp_keyring_packet_encode_header(packet);
}

pgp_error_t pgp_keyring_packet_add_subkey(pgp_keyring_packet *packet, byte_t subkey[PGP_KEY_MAX_FINGERPRINT_SIZE])
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

void pgp_keyring_packet_remove_subkey(pgp_keyring_packet *packet, byte_t subkey[PGP_KEY_MAX_FINGERPRINT_SIZE])
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

#define TO_UPPER(c) ((c) & ~0x20)
#define IS_HEX(c)   (((c) >= '0' && (c) <= '9') || (TO_UPPER((c)) >= 'A' && TO_UPPER((c)) <= 'F'))

// clang-format off
static const byte_t hex_to_nibble_table[256] = 
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,                       // 0 - 9
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // A - F
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // a - f
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};
// clang-format on

static void hex_to_data(void *input, byte_t input_size, byte_t output[PGP_KEY_MAX_FINGERPRINT_SIZE])
{
	byte_t *in = input;
	byte_t pos = 0;

	for (byte_t i = 0; i < input_size; i += 2)
	{
		output[pos++] = (hex_to_nibble_table[in[i]] << 4) + hex_to_nibble_table[in[i + 1]];
	}
}

static byte_t keyring_search_key_fingerprint_or_id_hex(pgp_keyring_packet *packet, void *input, uint32_t size,
													   byte_t output[PGP_KEY_MAX_FINGERPRINT_SIZE])
{
	if (size == packet->fingerprint_size)
	{
		// Check primary key first
		if (memcmp(packet->primary_fingerprint, input, packet->fingerprint_size) == 0)
		{
			memcpy(output, input, packet->fingerprint_size);
			return packet->fingerprint_size;
		}

		// Check subkeys in order
		for (byte_t i = 0; i < packet->subkey_count; ++i)
		{
			if (memcmp(PTR_OFFSET(packet->subkey_fingerprints, i * packet->fingerprint_size), input, packet->fingerprint_size) == 0)
			{
				memcpy(output, input, packet->fingerprint_size);
				return packet->fingerprint_size;
			}
		}
	}
	else // size == PGP_KEY_ID_SIZE
	{
		if (packet->key_version == PGP_KEY_V5)
		{
			// First 8 octets
			// Check primary key first
			if (memcmp(packet->primary_fingerprint, input, PGP_KEY_ID_SIZE) == 0)
			{
				memcpy(output, packet->primary_fingerprint, packet->fingerprint_size);
				return packet->fingerprint_size;
			}

			// Check subkeys in order
			for (byte_t i = 0; i < packet->subkey_count; ++i)
			{
				if (memcmp(PTR_OFFSET(packet->subkey_fingerprints, i * packet->fingerprint_size), input, PGP_KEY_ID_SIZE) == 0)
				{
					memcpy(output, PTR_OFFSET(packet->subkey_fingerprints, i * packet->fingerprint_size), packet->fingerprint_size);
					return packet->fingerprint_size;
				}
			}
		}
		else
		{
			// Last 8 octets
			// Check primary key first
			if (memcmp(PTR_OFFSET(packet->primary_fingerprint, packet->fingerprint_size - PGP_KEY_ID_SIZE), input, PGP_KEY_ID_SIZE) == 0)
			{
				memcpy(output, packet->primary_fingerprint, packet->fingerprint_size);
				return packet->fingerprint_size;
			}

			// Check subkeys in order
			for (byte_t i = 0; i < packet->subkey_count; ++i)
			{
				if (memcmp(PTR_OFFSET(packet->subkey_fingerprints,
									  (i * packet->fingerprint_size) + (packet->fingerprint_size - PGP_KEY_ID_SIZE)),
						   input, PGP_KEY_ID_SIZE) == 0)
				{
					memcpy(output, PTR_OFFSET(packet->subkey_fingerprints, i * packet->fingerprint_size), packet->fingerprint_size);
					return packet->fingerprint_size;
				}
			}
		}
	}

	return 0;
}

static byte_t keyring_search_key_fingerprint_or_id(pgp_keyring_packet *packet, void *input, uint32_t size,
												   byte_t output[PGP_KEY_MAX_FINGERPRINT_SIZE])
{
	byte_t *in = input;
	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};

	// Check for 0x and trailing !
	if (size % 4 != 0)
	{
		if (in[0] == '0' && TO_UPPER(in[1]) == 'X')
		{
			in += 2;
			size -= 2;
		}

		if (in[size - 1] == '!')
		{
			size -= 1;
		}
	}

	// Check valid hex characters
	if (size == 16 || size == (packet->fingerprint_size * 2))
	{
		for (byte_t i = 0; i < size; ++i)
		{
			if (!IS_HEX(in[i]))
			{
				return 0;
			}
		}
	}
	else
	{
		return 0;
	}

	// Convert to bytes
	hex_to_data(in, size, fingerprint);

	return keyring_search_key_fingerprint_or_id_hex(packet, fingerprint, size / 2, output);
}

static pgp_user_info *keyring_search_uid(pgp_keyring_packet *packet, void *input, uint32_t size)
{

	byte_t *in = input;
	byte_t match = 0;

	uint32_t uid_size = 0;
	pgp_user_info *user = NULL;

	if (in[0] == '<' || in[0] == '=' || in[0] == '@')
	{
		match = in[0];
		in += 1;
		size -= 1;
	}

	for (uint32_t i = 0; i < packet->users->count; ++i)
	{
		user = packet->users->packets[i];
		uid_size = user->uid_octets;

		// Absolute full uid match
		if (match == '=')
		{
			if (size == uid_size)
			{
				if (strncmp((void *)in, user->uid, uid_size) == 0)
				{
					return user;
				}
			}
		}

		// Full email match
		if (match == '<')
		{
			// TODO
		}

		// Partial email match
		if (match == '@')
		{
			// TODO
		}

		// Partial case insensitive match (TODO case)
		if (strstr(user->uid, (void *)in) != NULL)
		{
			return user;
		}
	}

	return NULL;
}

pgp_user_info *pgp_keyring_packet_search(pgp_keyring_packet *packet, void *input, uint32_t size)
{
	byte_t *in = input;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = 0;

	if (size == packet->fingerprint_size || size == PGP_KEY_ID_SIZE)
	{
		fingerprint_size = keyring_search_key_fingerprint_or_id_hex(packet, input, size, fingerprint);
		pgp_user_info *uinfo = packet->users->packets[0];

		if (fingerprint_size != 0)
		{
			// Use the primary user info and copy the fingerprint to it.
			memcpy(uinfo->fingerprint, fingerprint, fingerprint_size);
			uinfo->fingerprint_size = fingerprint_size;

			return uinfo;
		}
	}

	if (in[0] == '<' || in[0] == '=' || in[0] == '@')
	{
		return keyring_search_uid(packet, input, size);
	}

	if (size <= 67)
	{
		fingerprint_size = keyring_search_key_fingerprint_or_id(packet, input, size, fingerprint);
		pgp_user_info *uinfo = packet->users->packets[0];

		if (fingerprint_size != 0)
		{
			// Use the primary user info and copy the fingerprint to it.
			memcpy(uinfo->fingerprint, fingerprint, fingerprint_size);
			uinfo->fingerprint_size = fingerprint_size;

			return uinfo;
		}
	}

	// Assume uid
	return keyring_search_uid(packet, input, size);
}

static pgp_error_t pgp_user_info_read(pgp_user_info **info, buffer_t *buffer)
{
	pgp_user_info *user = NULL;

	uint32_t start = buffer->pos + 4;
	uint32_t info_octets = 0;
	uint32_t uid_octets = 0;
	uint32_t server_octets = 0;

	// A 4-octet info octets
	CHECK_READ(read32_be(buffer, &info_octets), PGP_MALFORMED_KEYRING_USER_INFO);

	// A 4-octet uid octets
	CHECK_READ(read32_be(buffer, &uid_octets), PGP_MALFORMED_KEYRING_USER_INFO);

	// A 4-octet server octets
	CHECK_READ(read32_be(buffer, &server_octets), PGP_MALFORMED_KEYRING_USER_INFO);

	user = malloc(sizeof(pgp_user_info));

	if (user == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(user, 0, sizeof(pgp_user_info));

	user->info_octets = info_octets;
	user->uid_octets = uid_octets;
	user->server_octets = server_octets;

	if (user->uid_octets > 0)
	{
		user->uid = malloc(user->uid_octets);

		if (user->uid == NULL)
		{
			pgp_user_info_delete(user);
			return PGP_NO_MEMORY;
		}

		memset(user->uid, 0, user->uid_octets);
	}

	if (user->server_octets > 0)
	{
		user->server = malloc(user->server_octets);

		if (user->server == NULL)
		{
			pgp_user_info_delete(user);
			return PGP_NO_MEMORY;
		}

		memset(user->server, 0, user->server_octets);
	}

	*info = user;

	// A 1-octet trust
	CHECK_READ(read8(buffer, &user->trust), PGP_MALFORMED_KEYRING_USER_INFO);

	// A 1-octet features
	CHECK_READ(read8(buffer, &user->features), PGP_MALFORMED_KEYRING_USER_INFO);

	// A 1-octet flags
	CHECK_READ(read8(buffer, &user->flags), PGP_MALFORMED_KEYRING_USER_INFO);

	// A 1-octet hash algorithm preferences count
	CHECK_READ(read8(buffer, &user->hash_algorithm_preferences_octets), PGP_MALFORMED_KEYRING_USER_INFO);

	// A 1-octet cipher algorithm preferences count
	CHECK_READ(read8(buffer, &user->cipher_algorithm_preferences_octets), PGP_MALFORMED_KEYRING_USER_INFO);

	// A 1-octet compression algorithm preferences count
	CHECK_READ(read8(buffer, &user->compression_algorithm_preferences_octets), PGP_MALFORMED_KEYRING_USER_INFO);

	// A 1-octet cipher mode preferences count
	CHECK_READ(read8(buffer, &user->cipher_modes_preferences_octets), PGP_MALFORMED_KEYRING_USER_INFO);

	// A 1-octet aead algorithm preferences count (octets)
	CHECK_READ(read8(buffer, &user->aead_algorithm_preferences_octets), PGP_MALFORMED_KEYRING_USER_INFO);

	// N-octets of uid
	if (user->uid_octets > 0)
	{
		CHECK_READ(readn(buffer, user->uid, user->uid_octets), PGP_MALFORMED_KEYRING_USER_INFO);
	}

	// N-octets of server
	if (user->server_octets > 0)
	{
		CHECK_READ(readn(buffer, user->server, user->server_octets), PGP_MALFORMED_KEYRING_USER_INFO);
	}

	// N-octet hash algorithm preferences
	if (user->hash_algorithm_preferences_octets > 0)
	{
		CHECK_READ(readn(buffer, user->hash_algorithm_preferences, user->hash_algorithm_preferences_octets),
				   PGP_MALFORMED_KEYRING_USER_INFO);
	}

	// N-octet cipher algorithm preferences
	if (user->cipher_algorithm_preferences_octets > 0)
	{
		CHECK_READ(readn(buffer, user->cipher_algorithm_preferences, user->cipher_algorithm_preferences_octets),
				   PGP_MALFORMED_KEYRING_USER_INFO);
	}

	// N-octet compression algorithm preferences
	if (user->compression_algorithm_preferences_octets > 0)
	{
		CHECK_READ(readn(buffer, user->compression_algorithm_preferences, user->compression_algorithm_preferences_octets),
				   PGP_MALFORMED_KEYRING_PACKET);
	}

	// N-octet cipher mode preferences
	if (user->cipher_modes_preferences_octets > 0)
	{
		CHECK_READ(readn(buffer, user->cipher_modes_preferences, user->cipher_modes_preferences_octets), PGP_MALFORMED_KEYRING_USER_INFO);
	}

	// N-octet aead algorithm preferences
	if (user->aead_algorithm_preferences_octets > 0)
	{
		CHECK_READ(readn(buffer, user->aead_algorithm_preferences, user->aead_algorithm_preferences_octets),
				   PGP_MALFORMED_KEYRING_USER_INFO);
	}

	// Check validity of the total octet count
	if (info_octets != buffer->pos - start)
	{
		return PGP_MALFORMED_KEYRING_USER_INFO;
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_keyring_packet_read_body(pgp_keyring_packet *packet, buffer_t *buffer)
{
	//  A 1-octet key version
	CHECK_READ(read8(buffer, &packet->key_version), PGP_MALFORMED_KEYRING_PACKET);

	// This is a private packet, catch any invalid values here.
	if (packet->key_version < PGP_KEY_V2 || packet->key_version > PGP_KEY_V6)
	{
		return PGP_UNKNOWN_KEY_VERSION;
	}

	packet->fingerprint_size = pgp_key_fingerprint_size(packet->key_version);

	// N octets of primary key fingerprint
	CHECK_READ(readn(buffer, packet->primary_fingerprint, packet->fingerprint_size), PGP_MALFORMED_KEYRING_PRIMARY_KEY);

	// A 4-octet subkey fingerprint size
	CHECK_READ(read32_be(buffer, &packet->subkey_size), PGP_MALFORMED_KEYRING_PACKET);

	if (packet->subkey_size > 0)
	{
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
	}

	// A 4-octet uid size
	CHECK_READ(read32_be(buffer, &packet->user_size), PGP_MALFORMED_KEYRING_PACKET);

	if (packet->user_size == 0)
	{
		return PGP_EMPTY_USER_ID;
	}

	while (buffer->pos < buffer->size)
	{
		pgp_error_t status = 0;
		pgp_user_info *user = NULL;
		void *result = NULL;

		status = pgp_user_info_read(&user, buffer);

		if (status != PGP_SUCCESS)
		{
			if (user != NULL)
			{
				pgp_user_info_delete(user);
			}

			return status;
		}

		result = pgp_stream_push(packet->users, user);

		if (result == NULL)
		{
			return PGP_NO_MEMORY;
		}

		packet->users = result;
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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_KEYRING)
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

static size_t pgp_user_info_write(pgp_user_info *user, void *ptr)
{
	byte_t *out = ptr;
	size_t pos = 0;

	// A 4-octet info octets
	LOAD_32BE(out + pos, &user->info_octets);
	pos += 4;

	// A 4-octet uid octets
	LOAD_32BE(out + pos, &user->uid_octets);
	pos += 4;

	// A 4-octet server octets
	LOAD_32BE(out + pos, &user->server_octets);
	pos += 4;

	// A 1-octet trust
	LOAD_8(out + pos, &user->trust);
	pos += 1;

	// A 1-octet features
	LOAD_8(out + pos, &user->features);
	pos += 1;

	// A 1-octet flags
	LOAD_8(out + pos, &user->flags);
	pos += 1;

	// A 1-octet hash algorithm preferences count
	LOAD_8(out + pos, &user->hash_algorithm_preferences_octets);
	pos += 1;

	// A 1-octet cipher algorithm preferences count
	LOAD_8(out + pos, &user->cipher_algorithm_preferences_octets);
	pos += 1;

	// A 1-octet compression algorithm preferences count
	LOAD_8(out + pos, &user->compression_algorithm_preferences_octets);
	pos += 1;

	// A 1-octet cipher mode preferences count
	LOAD_8(out + pos, &user->cipher_modes_preferences_octets);
	pos += 1;

	// A 1-octet aead algorithm preferences count (octets)
	LOAD_8(out + pos, &user->aead_algorithm_preferences_octets);
	pos += 1;

	// N-octets of uid
	memcpy(out + pos, user->uid, user->uid_octets);
	pos += user->uid_octets;

	// N-octets of server
	memcpy(out + pos, user->server, user->server_octets);
	pos += user->server_octets;

	// N-octet hash algorithm preferences
	memcpy(out + pos, user->hash_algorithm_preferences, user->hash_algorithm_preferences_octets);
	pos += user->hash_algorithm_preferences_octets;

	// N-octet cipher algorithm preferences
	memcpy(out + pos, user->cipher_algorithm_preferences, user->cipher_algorithm_preferences_octets);
	pos += user->cipher_algorithm_preferences_octets;

	// N-octet compression algorithm preferences
	memcpy(out + pos, user->compression_algorithm_preferences, user->compression_algorithm_preferences_octets);
	pos += user->compression_algorithm_preferences_octets;

	// N-octet cipher mode preferences
	memcpy(out + pos, user->cipher_modes_preferences, user->cipher_modes_preferences_octets);
	pos += user->cipher_modes_preferences_octets;

	// N-octet aead algorithm preferences
	memcpy(out + pos, user->aead_algorithm_preferences, user->aead_algorithm_preferences_octets);
	pos += user->aead_algorithm_preferences_octets;

	return pos;
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

	// N octets of primary key fingerprint
	memcpy(out + pos, packet->primary_fingerprint, packet->fingerprint_size);
	pos += packet->fingerprint_size;

	// A 4-octet subkey fingerprint size
	LOAD_32BE(out + pos, &packet->subkey_size);
	pos += 4;

	// N octets of subkey fingerprints.
	memcpy(out + pos, packet->subkey_fingerprints, packet->subkey_size);
	pos += packet->subkey_size;

	// A 4-octet uid size
	LOAD_32BE(out + pos, &packet->user_size);
	pos += 4;

	for (uint32_t i = 0; i < packet->users->count; ++i)
	{
		pos += pgp_user_info_write(packet->users->packets[i], out + pos);
	}

	return pos;
}

static inline uint16_t memchr_count(void *data, uint16_t size)
{
	void *result = 0;

	result = memchr(data, 0, size);

	if (result == NULL)
	{
		return size;
	}

	return (uint16_t)((uintptr_t)result - (uintptr_t)data);
}

pgp_error_t pgp_armor_packet_new(pgp_armor_packet **packet, void *marker, uint16_t marker_size, void *headers, uint16_t headers_size)
{
	pgp_armor_packet *armor = NULL;

	uint16_t pos = 0;
	uint16_t count = 0;
	uint16_t copy = 0;

	uint16_t size = 0;
	uint16_t offset = 0;

	byte_t version_size = 0;
	byte_t comment_size = 0;
	byte_t charset_size = 0;
	byte_t message_id_size = 0;

	while (pos < headers_size)
	{
		count = memchr_count(PTR_OFFSET(headers, pos), headers_size - pos);

		if (memcmp(PTR_OFFSET(headers, pos), "Version: ", 9) == 0)
		{
			version_size += (count - 9) + 1;
		}
		else if (memcmp(PTR_OFFSET(headers, pos), "Comment: ", 9) == 0)
		{
			comment_size += (count - 9) + 1;
		}
		else if (memcmp(PTR_OFFSET(headers, pos), "Hash: ", 6) == 0)
		{
			return PGP_ARMOR_HASH_HEADER_INVALID_USAGE;
		}
		else if (memcmp(PTR_OFFSET(headers, pos), "Charset: ", 9) == 0)
		{
			charset_size += (count - 9) + 1;
		}
		else if (memcmp(PTR_OFFSET(headers, pos), "MessageID: ", 11) == 0)
		{
			// This needs to be of length 32 only
			if ((count - 11) != 32)
			{
				return PGP_ARMOR_BAD_MESSAGE_ID;
			}

			message_id_size += (count - 11) + 1;
		}
		else
		{
			return PGP_ARMOR_UNKNOWN_HEADER;
		}

		pos += count + 1;
	}

	size = marker_size + version_size + comment_size + charset_size + message_id_size;

	armor = malloc(sizeof(pgp_armor_packet) + size);

	if (armor == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(armor, 0, sizeof(pgp_armor_packet) + size);

	// Load the marker
	armor->marker_size = marker_size;
	armor->marker = PTR_OFFSET(armor, sizeof(pgp_armor_packet) + offset);
	memcpy(armor->marker, marker, armor->marker_size);
	offset += armor->marker_size;

	// Version
	if (version_size > 0)
	{
		armor->version = PTR_OFFSET(armor, sizeof(pgp_armor_packet) + offset);
		offset += version_size;
	}

	// Comment
	if (comment_size > 0)
	{
		armor->comment = PTR_OFFSET(armor, sizeof(pgp_armor_packet) + offset);
		offset += comment_size;
	}

	// Charset
	if (charset_size > 0)
	{
		armor->marker = PTR_OFFSET(armor, sizeof(pgp_armor_packet) + offset);
		offset += charset_size;
	}

	// Message ID
	if (message_id_size > 0)
	{
		armor->marker = PTR_OFFSET(armor, sizeof(pgp_armor_packet) + offset);
		offset += message_id_size;
	}

	pos = 0;

	while (pos < headers_size)
	{
		count = memchr_count(PTR_OFFSET(headers, pos), headers_size - pos);

		if (memcmp(PTR_OFFSET(headers, pos), "Version: ", 9) == 0)
		{
			copy = (count - 9) + 1;

			memcpy(PTR_OFFSET(armor->version, armor->version_size), PTR_OFFSET(headers, pos + 9), copy);
			armor->version_size += copy;
		}
		else if (memcmp(PTR_OFFSET(headers, pos), "Comment: ", 9) == 0)
		{
			copy = (count - 9) + 1;

			memcpy(PTR_OFFSET(armor->comment, armor->comment_size), PTR_OFFSET(headers, pos + 9), copy);
			armor->comment_size += copy;
		}
		else if (memcmp(PTR_OFFSET(headers, pos), "Charset: ", 9) == 0)
		{
			copy = (count - 9) + 1;

			memcpy(PTR_OFFSET(armor->charset, armor->charset_size), PTR_OFFSET(headers, pos + 9), copy);
			armor->charset_size += copy;
		}
		else if (memcmp(PTR_OFFSET(headers, pos), "MessageID: ", 11) == 0)
		{
			copy = (count - 11) + 1;

			memcpy(PTR_OFFSET(armor->message_id, armor->message_id_size), PTR_OFFSET(headers, pos + 11), copy);
			armor->message_id_size += copy;
		}
		else
		{
			// Should be unreachable, as we are already checking this.
			return PGP_ARMOR_UNKNOWN_HEADER;
		}

		pos += count + 1;
	}

	// Set the header
	armor->header = pgp_packet_header_encode(PGP_HEADER, PGP_ARMOR, 0, size + 5);

	*packet = armor;

	return PGP_SUCCESS;
}

void pgp_armor_packet_delete(pgp_armor_packet *packet)
{
	free(packet);
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
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

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

pgp_error_t pgp_user_info_new(pgp_user_info **info, void *uid, uint32_t uid_size, void *server, uint32_t server_size, byte_t trust,
							  byte_t features, byte_t flags)
{
	pgp_user_info *user = NULL;

	if (uid == NULL || uid_size == 0)
	{
		return PGP_EMPTY_USER_ID;
	}

	if (trust != PGP_TRUST_NEVER && trust != PGP_TRUST_REVOKED && trust != PGP_TRUST_MARGINAL && trust != PGP_TRUST_FULL &&
		trust != PGP_TRUST_ULTIMATE)
	{
		return PGP_UNKNOWN_TRUST_LEVEL;
	}

	user = malloc(sizeof(pgp_user_info));

	if (user == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(user, 0, sizeof(pgp_user_info));

	user->trust = trust;
	user->features = features & PGP_FEATURE_FLAG_MASK;
	user->flags = flags & PGP_KEY_SERVER_FLAGS_MASK;

	user->uid_octets = uid_size;
	user->uid = malloc(user->uid_octets);

	if (user->uid == NULL)
	{
		pgp_user_info_delete(user);
		return PGP_NO_MEMORY;
	}

	memcpy(user->uid, uid, uid_size);

	if (server != NULL && server_size != 0)
	{
		user->server_octets = server_size;
		user->server = malloc(user->server_octets);

		if (user->server == NULL)
		{
			pgp_user_info_delete(user);
			return PGP_NO_MEMORY;
		}

		memcpy(user->server, server, server_size);
	}

	user->info_octets = 16 + user->uid_octets + user->server_octets;

	*info = user;

	return PGP_SUCCESS;
}

void pgp_user_info_delete(pgp_user_info *user)
{
	if (user == NULL)
	{
		return;
	}

	free(user->uid);
	free(user->server);
	free(user);
}

static pgp_error_t pgp_user_info_fill(pgp_user_info *user, pgp_stream_t *stream)
{
	pgp_error_t status = 0;
	pgp_subpacket_header *header = NULL;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];

		switch (header->tag & PGP_SUBPACKET_TAG_MASK)
		{
		case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
		{
			pgp_preferred_key_server_subpacket *subpacket = stream->packets[i];

			if (user->server == NULL)
			{
				if (subpacket->header.body_size > 0)
				{
					user->server_octets = subpacket->header.body_size;
					user->server = malloc(user->server_octets);

					if (user->server == NULL)
					{
						return PGP_NO_MEMORY;
					}

					memcpy(user->server, subpacket->server, user->server_octets);
				}
			}
		}
		break;
		case PGP_FEATURES_SUBPACKET:
		{
			pgp_features_subpacket *subpacket = stream->packets[i];

			if (user->features == 0)
			{
				for (uint32_t i = 0; i < subpacket->header.body_size; ++i)
				{
					user->features |= subpacket->flags[i];
				}
			}
		}
		break;
		case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
		{
			pgp_features_subpacket *subpacket = stream->packets[i];

			if (user->flags == 0)
			{
				for (uint32_t i = 0; i < subpacket->header.body_size; ++i)
				{
					user->flags |= subpacket->flags[i];
				}
			}
		}
		break;
		case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
		{
			pgp_preferred_symmetric_ciphers_subpacket *subpacket = stream->packets[i];

			if (user->cipher_algorithm_preferences_octets == 0)
			{
				status = pgp_user_info_set_cipher_preferences(user, subpacket->header.body_size, subpacket->preferred_algorithms);

				if (status != PGP_SUCCESS)
				{
					return status;
				}
			}
		}
		break;
		case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
		{
			pgp_preferred_hash_algorithms_subpacket *subpacket = stream->packets[i];

			if (user->hash_algorithm_preferences_octets == 0)
			{
				status = pgp_user_info_set_hash_preferences(user, subpacket->header.body_size, subpacket->preferred_algorithms);

				if (status != PGP_SUCCESS)
				{
					return status;
				}
			}
		}
		break;
		case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
		{
			pgp_preferred_compression_algorithms_subpacket *subpacket = stream->packets[i];

			if (user->compression_algorithm_preferences_octets == 0)
			{
				status = pgp_user_info_set_compression_preferences(user, subpacket->header.body_size, subpacket->preferred_algorithms);

				if (status != PGP_SUCCESS)
				{
					return status;
				}
			}
		}
		break;
		case PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET:
		{
			pgp_preferred_encryption_modes_subpacket *subpacket = stream->packets[i];

			if (user->cipher_modes_preferences_octets == 0)
			{
				status = pgp_user_info_set_mode_preferences(user, subpacket->header.body_size, subpacket->preferred_algorithms);

				if (status != PGP_SUCCESS)
				{
					return status;
				}
			}
		}
		break;
		case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
		{
			pgp_preferred_aead_ciphersuites_subpacket *subpacket = stream->packets[i];

			if (user->aead_algorithm_preferences_octets == 0)
			{
				status = pgp_user_info_set_aead_preferences(user, subpacket->header.body_size / 2, (void *)subpacket->preferred_algorithms);

				if (status != PGP_SUCCESS)
				{
					return status;
				}
			}
		}
		break;
		}
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_user_info_from_certificate(pgp_user_info **info, pgp_user_id_packet *user, pgp_signature_packet *sign)
{
	pgp_error_t status = 0;
	pgp_user_info *uinfo = NULL;

	void *uid = NULL;
	uint32_t uid_octets = 0;

	// Set uid fields first
	uid = &user->user_data;
	uid_octets = (uint32_t)user->header.body_size;

	if (uid_octets == 0)
	{
		return PGP_EMPTY_USER_ID;
	}

	if (*info == NULL)
	{
		status = pgp_user_info_new(&uinfo, uid, uid_octets, NULL, 0, 0, 0, 0);

		if (status != PGP_SUCCESS)
		{
			return status;
		}
	}
	else
	{
		uinfo = *info;
	}

	// Prefer data in hashed subpackets to unhashed ones
	status = pgp_user_info_fill(uinfo, sign->hashed_subpackets);

	if (status != PGP_SUCCESS)
	{
		pgp_user_info_delete(uinfo);
		return status;
	}

	status = pgp_user_info_fill(uinfo, sign->unhashed_subpackets);

	if (status != PGP_SUCCESS)
	{
		pgp_user_info_delete(uinfo);
		return status;
	}

	*info = uinfo;

	return PGP_SUCCESS;
}

pgp_error_t pgp_user_info_set_hash_preferences(pgp_user_info *user, byte_t count, byte_t preferences[])
{
	for (byte_t i = 0; i < count; ++i)
	{
		if (pgp_hash_algorithm_validate(preferences[i]) == 0)
		{
			return PGP_UNKNOWN_HASH_ALGORITHM;
		}
	}

	user->hash_algorithm_preferences_octets = count;
	memcpy(user->hash_algorithm_preferences, preferences, user->hash_algorithm_preferences_octets);

	user->info_octets += user->hash_algorithm_preferences_octets;

	return PGP_SUCCESS;
}

pgp_error_t pgp_user_info_set_cipher_preferences(pgp_user_info *user, byte_t count, byte_t preferences[])
{
	for (byte_t i = 0; i < count; ++i)
	{
		if (pgp_symmetric_cipher_algorithm_validate(preferences[i]) == 0)
		{
			return PGP_UNKNOWN_CIPHER_ALGORITHM;
		}
	}

	user->cipher_algorithm_preferences_octets = count;
	memcpy(user->cipher_algorithm_preferences, preferences, user->cipher_algorithm_preferences_octets);

	user->info_octets += user->cipher_algorithm_preferences_octets;

	return PGP_SUCCESS;
}

pgp_error_t pgp_user_info_set_compression_preferences(pgp_user_info *user, byte_t count, byte_t preferences[])
{
	for (byte_t i = 0; i < count; ++i)
	{
		if (preferences[i] != PGP_UNCOMPRESSED && preferences[i] != PGP_DEFALTE && preferences[i] != PGP_ZLIB &&
			preferences[i] != PGP_BZIP2)
		{
			return PGP_UNKNOWN_COMPRESSION_ALGORITHM;
		}
	}

	user->compression_algorithm_preferences_octets = count;
	memcpy(user->compression_algorithm_preferences, preferences, user->compression_algorithm_preferences_octets);

	user->info_octets += user->compression_algorithm_preferences_octets;

	return PGP_SUCCESS;
}

pgp_error_t pgp_user_info_set_mode_preferences(pgp_user_info *user, byte_t count, byte_t preferences[])
{
	for (byte_t i = 0; i < count; ++i)
	{
		if (pgp_aead_algorithm_validate(preferences[i]) == 0)
		{
			return PGP_UNKNOWN_AEAD_ALGORITHM;
		}
	}

	user->cipher_modes_preferences_octets = count;
	memcpy(user->cipher_modes_preferences, preferences, user->cipher_modes_preferences_octets);

	user->info_octets += user->cipher_modes_preferences_octets;

	return PGP_SUCCESS;
}

pgp_error_t pgp_user_info_set_aead_preferences(pgp_user_info *user, byte_t count, byte_t preferences[][2])
{
	for (byte_t i = 0; i < count; ++i)
	{
		if (pgp_aead_algorithm_validate(preferences[i][1]) == 0)
		{
			return PGP_UNKNOWN_AEAD_ALGORITHM;
		}

		if (pgp_symmetric_cipher_algorithm_validate(preferences[i][0]) == 0)
		{
			return PGP_UNKNOWN_CIPHER_ALGORITHM;
		}

		if (pgp_symmetric_cipher_block_size(preferences[i][0]) != 16)
		{
			return PGP_INVALID_AEAD_CIPHER_PAIR;
		}
	}

	user->aead_algorithm_preferences_octets = count * 2;
	memcpy(user->cipher_modes_preferences, preferences, user->aead_algorithm_preferences_octets);

	user->info_octets += user->aead_algorithm_preferences_octets;

	return PGP_SUCCESS;
}
