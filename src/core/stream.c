/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <stream.h>

#include <stdlib.h>
#include <string.h>

pgp_stream_t *pgp_stream_new(uint16_t capacity)
{
	pgp_stream_t *stream = NULL;
	void *packets = NULL;

	// Round to multiple of 4
	capacity = ROUND_UP(capacity, 4);

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

void pgp_stream_delete(pgp_stream_t *stream)
{
	if (stream == NULL)
	{
		return;
	}

	for (uint16_t i = 0; i < stream->count; ++i)
	{
		free(stream->packets[i]);
		stream->packets[i] = NULL;
	}

	free(stream->packets);
	free(stream);
}

pgp_stream_t *pgp_stream_read(void *data, size_t size)
{
	pgp_stream_t *stream = NULL;

	size_t pos = 0;
	uint16_t count = 0;

	// Check packet header validity and count the packets.
	while (pos < size)
	{
		pgp_packet_header header = pgp_packet_header_read(PTR_OFFSET(data, pos), size - pos);

		if (header.tag == 0)
		{
			return NULL;
		}

		if ((header.body_size + header.header_size) > (size - pos))
		{
			return NULL;
		}

		pos += header.body_size + header.header_size;
		count += 1;
	}

	stream = pgp_stream_new(count);

	if (stream == NULL)
	{
		return NULL;
	}

	pos = 0;
	count = 0;

	// Read the packets
	while (pos < size)
	{
		pgp_packet_header *header = NULL;
		void *packet = pgp_packet_read(PTR_OFFSET(data, pos), size - pos);

		if (packet == NULL)
		{
			pgp_stream_delete(stream);
			return NULL;
		}

		stream->packets[count] = packet;

		header = packet;
		pos += header->body_size + header->header_size;
		count += 1;
	}

	stream->count = count;

	return stream;
}

size_t pgp_stream_write(pgp_stream_t *stream, void *buffer, size_t size, uint16_t options)
{
	pgp_packet_header *header = NULL;
	size_t pos = 0;

	for (uint16_t i = 0; i < stream->count; ++i)
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

size_t pgp_stream_print(pgp_stream_t *stream, void *buffer, size_t size, uint16_t options)
{
	size_t pos = 0;

	for (uint16_t i = 0; i < stream->count; ++i)
	{
		pos += pgp_packet_print(stream->packets[i], PTR_OFFSET(buffer, pos), size - pos, options);
	}

	return pos;
}
