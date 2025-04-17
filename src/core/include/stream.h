/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_STREAM_H
#define SPGP_STREAM_H

#include <pgp.h>
#include <error.h>

typedef struct _pgp_stream_t
{
	uint16_t count;
	uint16_t capacity;

	void **packets;
} pgp_stream_t;

pgp_stream_t *pgp_stream_new(uint16_t capacity);
void pgp_stream_delete(pgp_stream_t *stream, void (*deleter)(void *));

size_t pgp_stream_octets(pgp_stream_t *stream);
size_t pgp_stream_armor_size(pgp_stream_t *stream);

pgp_error_t pgp_stream_read(pgp_stream_t *stream, void *data, size_t size);
size_t pgp_stream_write(pgp_stream_t *stream, void *buffer, size_t size, uint16_t options);
size_t pgp_stream_print(pgp_stream_t *stream, void *buffer, size_t size, uint16_t options);

pgp_stream_t *pgp_stream_push_packet(pgp_stream_t *stream, void *packet);
void *pgp_stream_pop_packet(pgp_stream_t *stream);

#endif
