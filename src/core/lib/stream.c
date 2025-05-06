/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
#include <armor.h>
#include <packet.h>
#include <stream.h>

#include <stdlib.h>
#include <string.h>

pgp_stream_t *pgp_stream_new(uint32_t capacity)
{
	pgp_stream_t *stream = NULL;
	void *packets = NULL;

	// Round to multiple of 4
	capacity = ROUND_UP(MAX(capacity, 1), 4);

	stream = malloc(sizeof(pgp_stream_t));
	packets = malloc(sizeof(void *) * capacity);

	if (stream == NULL || packets == NULL)
	{
		free(stream);
		free(packets);

		return NULL;
	}

	memset(stream, 0, sizeof(pgp_stream_t));
	memset(packets, 0, sizeof(void *) * capacity);

	stream->capacity = capacity;
	stream->packets = packets;

	return stream;
}

void pgp_stream_delete(pgp_stream_t *stream, void (*deleter)(void *))
{
	if (stream == NULL)
	{
		return;
	}

	if (deleter == NULL)
	{
		goto end;
	}

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		deleter(stream->packets[i]);
		stream->packets[i] = NULL;
	}

end:
	free(stream->packets);
	free(stream);
}

size_t pgp_stream_octets(pgp_stream_t *stream)
{
	pgp_packet_header *header = NULL;
	size_t size = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];
		size += header->body_size + header->header_size;
	}

	return size;
}

pgp_stream_t *pgp_stream_push_packet(pgp_stream_t *stream, void *packet)
{
	void *temp = NULL;

	if (stream == NULL)
	{
		stream = pgp_stream_new(4);

		if (stream == NULL)
		{
			return NULL;
		}
	}

	if (stream->count == stream->capacity)
	{
		stream->capacity *= 2;
		temp = realloc(stream->packets, sizeof(void *) * stream->capacity);

		if (temp == NULL)
		{
			return NULL;
		}

		stream->packets = temp;
	}

	stream->packets[stream->count] = packet;
	stream->count += 1;

	return stream;
}

void *pgp_stream_pop_packet(pgp_stream_t *stream)
{
	void *packet = NULL;

	if (stream->count == 0)
	{
		return NULL;
	}

	packet = stream->packets[stream->count];
	stream->packets[stream->count] = NULL;
	stream->count -= 1;

	return packet;
}

pgp_error_t pgp_stream_read(pgp_stream_t *stream, void *data, size_t size)
{
	pgp_error_t error = 0;
	size_t pos = 0;

	// Check packet header validity and count the packets.
	while (pos < size)
	{
		pgp_packet_header *header = NULL;
		void *packet = NULL;

		error = pgp_packet_read(&packet, PTR_OFFSET(data, pos), size - pos);

		if (error != PGP_SUCCESS)
		{
			pgp_stream_delete(stream, pgp_packet_delete);
			return error;
		}

		stream = pgp_stream_push_packet(stream, packet);

		if (stream == NULL)
		{
			pgp_stream_delete(stream, pgp_packet_delete);
			return PGP_NO_MEMORY;
		}

		header = packet;
		pos += header->body_size + header->header_size;

		if (header->partial_begin)
		{
			while (pos < size)
			{
				error = pgp_partial_packet_read(&packet, PTR_OFFSET(data, pos), size - pos);

				if (error != PGP_SUCCESS)
				{
					pgp_stream_delete(stream, pgp_packet_delete);
					return error;
				}

				stream = pgp_stream_push_packet(stream, packet);

				if (stream == NULL)
				{
					pgp_stream_delete(stream, pgp_packet_delete);
					return PGP_NO_MEMORY;
				}

				header = packet;
				pos += header->body_size + header->header_size;

				if (header->partial_end)
				{
					break;
				}
			}
		}
	}

	return error;
}

size_t pgp_stream_write(pgp_stream_t *stream, void *buffer, size_t size)
{
	pgp_packet_header *header = NULL;
	size_t pos = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];

		// Write complete packets only
		if ((header->body_size + header->header_size) < (size - pos))
		{
			break;
		}

		pos += pgp_packet_write(stream->packets[i], PTR_OFFSET(buffer, pos), size - pos);
	}

	return pos;
}

pgp_error_t pgp_stream_read_armor(pgp_stream_t *stream, void *buffer, uint32_t buffer_size, uint16_t flags)
{
	pgp_error_t error = 0;
	armor_status status = 0;

	armor_options options = {0};
	armor_marker markers[] = {{.header_line = (void *)PGP_ARMOR_BEGIN_MESSAGE,
							   .header_line_size = strlen(PGP_ARMOR_BEGIN_MESSAGE),
							   .trailer_line = (void *)PGP_ARMOR_END_MESSAGE,
							   .trailer_line_size = strlen(PGP_ARMOR_END_MESSAGE)},
							  {.header_line = (void *)PGP_ARMOR_BEGIN_PUBLIC_KEY,
							   .header_line_size = strlen(PGP_ARMOR_BEGIN_PUBLIC_KEY),
							   .trailer_line = (void *)PGP_ARMOR_END_PUBLIC_KEY,
							   .trailer_line_size = strlen(PGP_ARMOR_END_PUBLIC_KEY)},
							  {.header_line = (void *)PGP_ARMOR_BEGIN_PRIVATE_KEY,
							   .header_line_size = strlen(PGP_ARMOR_BEGIN_PRIVATE_KEY),
							   .trailer_line = (void *)PGP_ARMOR_END_PRIVATE_KEY,
							   .trailer_line_size = strlen(PGP_ARMOR_END_PRIVATE_KEY)},
							  {.header_line = (void *)PGP_ARMOR_BEGIN_SIGNATURE,
							   .header_line_size = strlen(PGP_ARMOR_BEGIN_SIGNATURE),
							   .trailer_line = (void *)PGP_ARMOR_END_SIGNATURE,
							   .trailer_line_size = strlen(PGP_ARMOR_END_SIGNATURE)}};

	void *temp = NULL;
	uint32_t temp_size = buffer_size;

	uint32_t pos = 0;
	byte_t first_packet = 0;

	uint32_t input_pos = 0;
	uint32_t input_size = 0;
	uint32_t output_pos = 0;
	uint32_t output_size = 0;

	temp = malloc(temp_size);

	if (temp == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(temp, 0, temp_size);

	options.flags = (ARMOR_SCAN_HEADERS | ARMOR_EMPTY_LINE) | (flags & PGP_ARMOR_NO_CRC ? ARMOR_CHECKSUM_CRC24 : 0);

	while (pos < buffer_size)
	{
		input_pos += input_size;
		output_pos += output_size;

		input_size = buffer_size - input_size;
		output_size = temp_size - output_size;

		status = armor_read(&options, markers, 4, PTR_OFFSET(buffer, input_pos), &input_size, PTR_OFFSET(temp, output_pos), &output_size);

		if (status != ARMOR_SUCCESS)
		{
			switch (status)
			{
			case ARMOR_UNKOWN_MARKER:
				error = PGP_ARMOR_UNKNOWN_MARKER;
				break;
			case ARMOR_MARKER_MISMATCH:
				error = PGP_ARMOR_MARKER_MISMATCH;
				break;
			case ARMOR_MALFORMED_DATA:
				error = PGP_ARMOR_MALFORMED_BASE64_DATA;
				break;
			case ARMOR_CRC_MISMATCH:
				error = PGP_ARMOR_CRC_MISMATCH;
				break;
			case ARMOR_LINE_TOO_BIG:
				error = PGP_ARMOR_LINE_TOO_BIG;
				break;
			case ARMOR_BUFFER_TOO_SMALL:
				error = PGP_BUFFER_TOO_SMALL;
				break;
			case ARMOR_NO_MEMORY:
				error = PGP_NO_MEMORY;
				break;
			default:
				error = PGP_INTERNAL_BUG;
				break;
			}

			goto error_cleanup;
		}

		// Ignore the headers
		if (options.headers != NULL)
		{
			free(options.headers);

			options.headers = NULL;
			options.headers_size = 0;
		}

		first_packet = 0;

		while (pos < output_size)
		{
			pgp_packet_header *header = NULL;
			pgp_packet_type type = 0;
			void *packet = NULL;

			error = pgp_packet_read(&packet, PTR_OFFSET(temp, output_pos + pos), output_size - pos);

			if (error != PGP_SUCCESS)
			{
				goto error_cleanup;
			}

			header = packet;
			type = pgp_packet_get_type(header->tag);
			pos += header->body_size + header->header_size;

			// Check whether the armor content is valid for the corresponding marker
			if (first_packet)
			{
				// PGP PUBLIC KEY BLOCK
				if (options.marker == &markers[1])
				{
					if (type != PGP_PUBKEY)
					{
						error = PGP_ARMOR_INVALID_MARKER_FOR_TRANSFERABLE_PUBLIC_KEY;
						goto error_cleanup;
					}
				}

				// PGP PRIVATE KEY BLOCK
				if (options.marker == &markers[2])
				{
					if (type != PGP_SECKEY)
					{
						error = PGP_ARMOR_INVALID_MARKER_FOR_TRANSFERABLE_SECRET_KEY;
						goto error_cleanup;
					}
				}

				// PGP SIGNATURE
				if (options.marker == &markers[3])
				{
					if (type != PGP_SIG && type != PGP_OPS)
					{
						error = PGP_ARMOR_INVALID_MARKER_FOR_SIGNATURE;
						goto error_cleanup;
					}
				}
			}

			stream = pgp_stream_push_packet(stream, packet);

			if (stream == NULL)
			{
				error = PGP_NO_MEMORY;
				goto error_cleanup;
			}

			first_packet += 1;
		}
	}

	free(temp);

end:
	return error;

error_cleanup:
	free(temp);
	pgp_stream_delete(stream, pgp_packet_delete);
	goto end;
}

size_t pgp_stream_write_armor(pgp_stream_t *stream, void *buffer, uint32_t buffer_size, void *header, uint16_t header_size, uint16_t flags)
{
	armor_status status = 0;
	pgp_packet_header *packet_header = NULL;
	size_t pos = 0;

	void *temp = NULL;
	size_t temp_size = pgp_stream_octets(stream);

	pgp_packet_type packet_type = 0;
	armor_marker marker = {0};
	armor_options options = {0};

	temp = malloc(temp_size);

	if (temp == NULL)
	{
		return 0;
	}

	memset(temp, 0, temp_size);

	// Determine armor type
	packet_header = stream->packets[0];
	packet_type = pgp_packet_get_type(packet_header->tag);

	if (packet_type == PGP_SIG || packet_type == PGP_OPS)
	{
		marker.header_line = (void *)PGP_ARMOR_BEGIN_SIGNATURE;
		marker.header_line_size = strlen(PGP_ARMOR_BEGIN_SIGNATURE);
		marker.trailer_line = (void *)PGP_ARMOR_END_SIGNATURE;
		marker.trailer_line_size = strlen(PGP_ARMOR_END_SIGNATURE);
	}
	else if (packet_type == PGP_PUBKEY)
	{
		marker.header_line = (void *)PGP_ARMOR_BEGIN_PUBLIC_KEY;
		marker.header_line_size = strlen(PGP_ARMOR_BEGIN_PUBLIC_KEY);
		marker.trailer_line = (void *)PGP_ARMOR_END_PUBLIC_KEY;
		marker.trailer_line_size = strlen(PGP_ARMOR_END_PUBLIC_KEY);
	}
	else if (packet_type == PGP_SECKEY)
	{
		marker.header_line = (void *)PGP_ARMOR_BEGIN_PRIVATE_KEY;
		marker.header_line_size = strlen(PGP_ARMOR_BEGIN_PRIVATE_KEY);
		marker.trailer_line = (void *)PGP_ARMOR_END_PRIVATE_KEY;
		marker.trailer_line_size = strlen(PGP_ARMOR_END_PRIVATE_KEY);
	}
	else
	{
		marker.header_line = (void *)PGP_ARMOR_BEGIN_MESSAGE;
		marker.header_line_size = strlen(PGP_ARMOR_BEGIN_MESSAGE);
		marker.trailer_line = (void *)PGP_ARMOR_END_MESSAGE;
		marker.trailer_line_size = strlen(PGP_ARMOR_END_MESSAGE);
	}

	options.marker = &marker;
	options.flags = ARMOR_EMPTY_LINE | (flags & PGP_ARMOR_NO_CRC ? ARMOR_CHECKSUM_CRC24 : 0);
	options.headers = header;
	options.headers_size = header_size;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		packet_header = stream->packets[i];
		pos += pgp_packet_write(stream->packets[i], PTR_OFFSET(temp, pos), temp_size - pos);
	}

	status = armor_write(&options, temp, pos, buffer, &buffer_size);

	free(temp);

	if (status != ARMOR_SUCCESS)
	{
		return 0;
	}

	return buffer_size;
}

size_t pgp_stream_print(pgp_stream_t *stream, void *buffer, size_t size, uint16_t options)
{
	size_t pos = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		if (options & PGP_PRINT_HEADER_ONLY)
		{
			pos += pgp_packet_header_print(stream->packets[i], PTR_OFFSET(buffer, pos), size - pos);
			continue;
		}

		pos += pgp_packet_print(stream->packets[i], PTR_OFFSET(buffer, pos), size - pos, options & PGP_PRINT_MPI_MINIMAL);
	}

	return pos;
}
