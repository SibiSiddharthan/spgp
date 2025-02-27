/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <armor.h>
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

size_t pgp_stream_octets(pgp_stream_t *stream)
{
	pgp_packet_header *header = NULL;
	size_t size = 0;

	for (uint16_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];
		size += header->body_size + header->header_size;
	}

	return size;
}

size_t pgp_stream_armor_size(pgp_stream_t *stream)
{
	return (CEIL_DIV(pgp_stream_octets(stream), 3) * 4) + 128; // header and footer
}

static size_t pgp_stream_write_armor(pgp_stream_t *stream, void *buffer, size_t size, uint32_t options)
{
	pgp_packet_header *header = NULL;
	pgp_armor_ctx *armor = NULL;
	void *temp = NULL;

	size_t pos = 0;
	size_t result = 0;

	size_t temp_size = pgp_stream_octets(stream);
	size_t armor_size = (CEIL_DIV(temp_size, 3) * 4) + 128;

	pgp_armor_type armor_type = 0;
	pgp_packet_type packet_type = 0;

	// Make sure we can output the entire armor stream
	if (size < armor_size)
	{
		return 0;
	}

	temp = malloc(temp_size);

	if (temp == NULL)
	{
		return 0;
	}

	memset(temp, 0, temp_size);

	// Determine armor type
	header = stream->packets[0];
	packet_type = pgp_packet_get_type(header->tag);

	if (packet_type == PGP_SIG)
	{
		armor_type = PGP_ARMOR_SIGNATURE;
	}
	else if (packet_type == PGP_PUBKEY || packet_type == PGP_PUBSUBKEY)
	{
		armor_type = PGP_ARMOR_PUBLIC_KEY;
	}
	else if (packet_type == PGP_SECKEY || packet_type == PGP_SECSUBKEY)
	{
		armor_type = PGP_ARMOR_PRIVATE_KEY;
	}
	else
	{
		armor_type = PGP_ARMOR_MESSAGE;
	}

	armor = pgp_armor_new(armor_type, (options & PGP_WRITE_ARMOR_NO_CRC) ? PGP_ARMOR_NO_CRC : 0);

	if (armor == NULL)
	{
		free(temp);
		return 0;
	}

	for (uint16_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];
		pos += pgp_packet_write(stream->packets[i], PTR_OFFSET(temp, pos), size - pos);
	}

	armor->data.size = temp_size;
	armor->data.capacity = temp_size;
	armor->data.data = temp;

	pgp_armor_write(armor, buffer, size, &result);

	pgp_armor_delete(armor);
	free(temp); // TODO should be moved into pgp_armor_delete itself

	return result;
}

static size_t pgp_stream_write_binary(pgp_stream_t *stream, void *buffer, size_t size)
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

static pgp_stream_t *pgp_stream_read_armor(void *data, size_t size)
{
	armor_status status = 0;

	pgp_stream_t *stream = NULL;
	pgp_armor_ctx *armor = NULL;

	pgp_packet_header *header = NULL;
	void *packet = NULL;

	size_t pos = 0;
	size_t offset = 0;
	size_t result = 0;

	stream = pgp_stream_new(4);

	if (stream == NULL)
	{
		return NULL;
	}

	while (pos < size)
	{
		status = pgp_armor_read(armor, PTR_OFFSET(data, pos), size - pos, &result);

		if (status != ARMOR_SUCCESS)
		{
			pgp_armor_delete(armor);
			pgp_stream_delete(stream);
			return NULL;
		}

		while (offset < armor->data.size)
		{
			packet = pgp_packet_read(PTR_OFFSET(armor->data.data, offset), armor->data.size);

			if (packet == NULL)
			{
				pgp_stream_delete(stream);
				pgp_armor_delete(armor);

				return NULL;
			}

			header = packet;
			offset += header->body_size + header->header_size;

			if (pgp_stream_push_packet(stream, packet) == NULL)
			{
				pgp_stream_delete(stream);
				pgp_armor_delete(armor);
			}
		}

		pos += result;
	}

	return stream;
}

static pgp_stream_t *pgp_stream_read_binary(void *data, size_t size)
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

pgp_stream_t *pgp_stream_read(void *data, size_t size)
{
	byte_t *in = data;

	// Check if data is armored
	if (pgp_packet_validate_tag(in[0]) == 0)
	{
		return pgp_stream_read_armor(data, size);
	}

	return pgp_stream_read_binary(data, size);
}

size_t pgp_stream_write(pgp_stream_t *stream, void *buffer, size_t size, uint16_t options)
{
	if (options & PGP_WRITE_ARMOR)
	{
		return pgp_stream_write_armor(stream, buffer, size, options);
	}

	return pgp_stream_write_binary(stream, buffer, size);
}

size_t pgp_stream_print(pgp_stream_t *stream, void *buffer, size_t size, uint16_t options)
{
	size_t pos = 0;

	for (uint16_t i = 0; i < stream->count; ++i)
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

pgp_stream_t *pgp_stream_push_packet(pgp_stream_t *stream, void *packet)
{
	void *temp = NULL;

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

	stream->packets[stream->count++] = packet;

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

	return packet;
}
