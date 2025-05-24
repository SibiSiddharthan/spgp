/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
#include <armor.h>
#include <packet.h>
#include <stream.h>
#include <seipd.h>
#include <signature.h>

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

pgp_stream_t *pgp_stream_clear(pgp_stream_t *stream, void (*deleter)(void *))
{

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		if (deleter != NULL)
		{
			deleter(stream->packets[i]);
		}

		stream->packets[i] = NULL;
	}

	stream->count = 0;

	return stream;
}

pgp_stream_t *pgp_stream_push(pgp_stream_t *stream, void *packet)
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

void *pgp_stream_pop(pgp_stream_t *stream)
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

void *pgp_stream_remove(pgp_stream_t *stream, uint32_t index)
{
	void *packet = NULL;

	if (stream->count <= index)
	{
		return NULL;
	}

	packet = stream->packets[index];

	memmove(&stream->packets[index], &stream->packets[index + 1], (stream->count - (index + 1)) * sizeof(void *));
	stream->packets[stream->count - 1] = NULL;
	stream->count -= 1;

	return packet;
}

pgp_error_t pgp_packet_stream_read(pgp_stream_t **stream, void *data, size_t size)
{
	pgp_error_t error = 0;
	size_t pos = 0;

	pgp_stream_t *out = NULL;
	void *result = NULL;

	while (pos < size)
	{
		pgp_packet_header *header = NULL;
		void *packet = NULL;

		error = pgp_packet_read(&packet, PTR_OFFSET(data, pos), size - pos);

		if (error != PGP_SUCCESS)
		{
			pgp_stream_delete(out, pgp_packet_delete);
			return error;
		}

		result = pgp_stream_push(out, packet);

		if (result == NULL)
		{
			pgp_stream_delete(out, pgp_packet_delete);
			return PGP_NO_MEMORY;
		}

		out = result;

		header = packet;
		pos += header->body_size + header->header_size;

		if (header->partial_begin)
		{
			while (pos < size)
			{
				error = pgp_partial_packet_read(&packet, PTR_OFFSET(data, pos), size - pos);

				if (error != PGP_SUCCESS)
				{
					pgp_stream_delete(out, pgp_packet_delete);
					return error;
				}

				result = pgp_stream_push(out, packet);

				if (result == NULL)
				{
					pgp_stream_delete(out, pgp_packet_delete);
					return PGP_NO_MEMORY;
				}

				out = result;

				header = packet;
				pos += header->body_size + header->header_size;

				if (header->partial_end)
				{
					break;
				}
			}
		}
	}

	*stream = out;

	return error;
}

pgp_error_t pgp_packet_stream_write(pgp_stream_t *stream, void **buffer, size_t *size)
{
	size_t pos = 0;

	*size = pgp_packet_stream_octets(stream);
	*buffer = malloc(*size);

	if (*buffer == NULL)
	{
		return PGP_NO_MEMORY;
	}

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		pos += pgp_packet_write(stream->packets[i], PTR_OFFSET(*buffer, pos), *size - pos);
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_packet_stream_read_armor(pgp_stream_t **stream, void *buffer, uint32_t buffer_size)
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

	pgp_stream_t *out = NULL;

	temp = malloc(temp_size);

	if (temp == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(temp, 0, temp_size);

	options.flags = (ARMOR_SCAN_HEADERS | ARMOR_EMPTY_LINE | ARMOR_CHECKSUM_CRC24 | ARMOR_IGNORE_UNKNOWN_MARKERS);

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
			void *result = NULL;

			error = pgp_packet_read(&packet, PTR_OFFSET(temp, output_pos + pos), output_size - pos);

			if (error != PGP_SUCCESS)
			{
				goto error_cleanup;
			}

			header = packet;
			type = pgp_packet_type_from_tag(header->tag);
			pos += header->body_size + header->header_size;

			// Check whether the armor content is valid for the corresponding marker
			if (first_packet)
			{
				// PGP PUBLIC KEY BLOCK
				if (options.marker == &markers[1])
				{
					if (type != PGP_PUBKEY && type != PGP_COMP)
					{
						error = PGP_ARMOR_INVALID_MARKER_FOR_TRANSFERABLE_PUBLIC_KEY;
						goto error_cleanup;
					}
				}

				// PGP PRIVATE KEY BLOCK
				if (options.marker == &markers[2])
				{
					if (type != PGP_SECKEY && type != PGP_COMP)
					{
						error = PGP_ARMOR_INVALID_MARKER_FOR_TRANSFERABLE_SECRET_KEY;
						goto error_cleanup;
					}
				}

				// PGP SIGNATURE
				if (options.marker == &markers[3])
				{
					if (type != PGP_SIG && type != PGP_OPS && type != PGP_COMP)
					{
						error = PGP_ARMOR_INVALID_MARKER_FOR_SIGNATURE;
						goto error_cleanup;
					}
				}
			}

			result = pgp_stream_push(out, packet);

			if (result == NULL)
			{
				error = PGP_NO_MEMORY;
				goto error_cleanup;
			}

			out = result;

			first_packet += 1;
		}
	}

	free(temp);

	*stream = out;

end:
	return error;

error_cleanup:
	free(temp);
	pgp_stream_delete(out, pgp_packet_delete);
	goto end;
}

pgp_error_t pgp_packet_stream_write_armor(pgp_stream_t *stream, armor_options *options, void **buffer, size_t *size)
{
	pgp_error_t error = 0;
	armor_status status = 0;

	void *temp = NULL;
	size_t temp_size = 0;

	error = pgp_packet_stream_write(stream, &temp, &temp_size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	*size = ((temp_size * 4) / 3) + 128; // Rough estimate

	if (*size > ((uint64_t)1 << 32))
	{
		return PGP_ARMOR_TOO_BIG;
	}

	// Always add empty line after begin marker
	options->flags |= ARMOR_EMPTY_LINE;

	if (status != ARMOR_SUCCESS)
	{
		if (status == ARMOR_BUFFER_TOO_SMALL)
		{
			*buffer = realloc(*buffer, *size);

			if (*buffer == NULL)
			{
				return PGP_NO_MEMORY;
			}

			status = armor_write(options, temp, (uint32_t)temp_size, *buffer, (uint32_t *)size);
		}

		if (status != ARMOR_SUCCESS)
		{
			// This is the only error that can occur
			error = PGP_BUFFER_TOO_SMALL;
			free(*buffer);
		}
	}

	free(temp);

	return PGP_SUCCESS;
}

size_t pgp_packet_stream_octets(pgp_stream_t *stream)
{
	pgp_packet_header *header = NULL;
	pgp_packet_type type = 0;
	size_t size = 0;

	if (stream == NULL)
	{
		return 0;
	}

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];
		type = pgp_packet_type_from_tag(header->tag);

		size += PGP_PACKET_OCTETS(*header);

		if (type == PGP_COMP || type == PGP_LIT || type == PGP_SED || type == PGP_SEIPD || type == PGP_AEAD)
		{
			// Count the partials
			size += pgp_packet_stream_octets(((pgp_data_packet *)stream->packets[i])->partials);
		}
	}

	return size;
}

size_t pgp_packet_stream_print(pgp_stream_t *stream, void *buffer, size_t size, uint16_t options)
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

pgp_stream_t *pgp_packet_stream_filter_padding_packets(pgp_stream_t *stream)
{
	pgp_packet_header *header = NULL;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];

		if (pgp_packet_type_from_tag(header->tag) == PGP_MARKER || pgp_packet_type_from_tag(header->tag) == PGP_PADDING)
		{
			pgp_stream_remove(stream, i);
			pgp_packet_delete(header);

			--i;
		}
	}

	return stream;
}

pgp_stream_t *pgp_packet_stream_filter_non_exportable_signatures(pgp_stream_t *stream)
{
	pgp_packet_header *header = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_exportable_subpacket *exportable = NULL;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];

		if (pgp_packet_type_from_tag(header->tag) == PGP_SIG)
		{
			pgp_subpacket_header *subheader = NULL;

			sign = stream->packets[i];

			// Search hashed first
			if (sign->hashed_subpackets != NULL)
			{
				for (uint32_t j = 0; j < sign->hashed_subpackets->count; ++j)
				{
					subheader = sign->hashed_subpackets->packets[i];

					if ((subheader->tag & PGP_SUBPACKET_TAG_MASK) == PGP_EXPORTABLE_SUBPACKET)
					{
						exportable = sign->hashed_subpackets->packets[i];

						if (exportable->state == 0)
						{
							goto remove_signature;
						}
					}
				}
			}

			if (sign->unhashed_subpackets != NULL)
			{
				for (uint32_t j = 0; j < sign->unhashed_subpackets->count; ++j)
				{
					subheader = sign->unhashed_subpackets->packets[i];

					if ((subheader->tag & PGP_SUBPACKET_TAG_MASK) == PGP_EXPORTABLE_SUBPACKET)
					{
						exportable = sign->unhashed_subpackets->packets[i];

						if (exportable->state == 0)
						{
							goto remove_signature;
						}
					}
				}
			}

			continue;

		remove_signature:
			pgp_stream_remove(stream, i);
			pgp_signature_packet_delete(sign);

			--i;

			continue;
		}
	}

	return stream;
}

pgp_stream_t *pgp_packet_stream_collate_partials(pgp_stream_t *stream)
{
	pgp_packet_header *header = NULL;
	pgp_stream_t *partials = NULL;
	void *result = NULL;
	uint32_t index = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];

		if (header->partial_begin)
		{
			index = i + 1;
			partials = NULL;

			do
			{
				header = stream->packets[index];
				result = pgp_stream_push(partials, stream->packets[index]);

				if (result == NULL)
				{
					pgp_stream_delete(partials, (void (*)(void *))pgp_partial_packet_delete);
					return NULL;
				}

				partials = result;

				pgp_stream_remove(stream, index);

			} while (header->partial_end == 0);

			header = stream->packets[i];

			switch (pgp_packet_type_from_tag(header->tag))
			{
			case PGP_COMP:
				((pgp_compresed_packet *)stream->packets[i])->partials = partials;
				break;
			case PGP_SED:
				((pgp_sed_packet *)stream->packets[i])->partials = partials;
				break;
			case PGP_LIT:
				((pgp_literal_packet *)stream->packets[i])->partials = partials;
				break;
			case PGP_SEIPD:
				((pgp_seipd_packet *)stream->packets[i])->partials = partials;
				break;
			case PGP_AEAD:
				((pgp_aead_packet *)stream->packets[i])->partials = partials;
				break;

			default:
				// This should never happen.
				pgp_stream_delete(partials, (void (*)(void *))pgp_partial_packet_delete);
			}
		}
	}

	return stream;
}
