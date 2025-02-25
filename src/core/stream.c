/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <stream.h>

#include <stdlib.h>
#include <string.h>

pgp_stream_t *pgp_stream_new(uint16_t capacity)
{
	pgp_stream_t *stream = NULL;
	void *packets = NULL;

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
