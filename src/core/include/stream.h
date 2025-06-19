/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_STREAM_H
#define SPGP_STREAM_H

#include <pgp.h>
#include <armor.h>
#include <error.h>

typedef struct _pgp_stream_t
{
	uint32_t count;
	uint32_t capacity;

	union
	{
		void **packets;
		void **data;
	};

} pgp_stream_t;

pgp_stream_t *pgp_stream_new(uint32_t capacity);
pgp_stream_t *pgp_stream_clear(pgp_stream_t *stream, void (*deleter)(void *));
void pgp_stream_delete(pgp_stream_t *stream, void (*deleter)(void *));

pgp_stream_t *pgp_stream_push(pgp_stream_t *stream, void *packet);
pgp_stream_t *pgp_stream_insert(pgp_stream_t *stream, void *packet, uint32_t index);
void *pgp_stream_pop(pgp_stream_t *stream);
void *pgp_stream_remove(pgp_stream_t *stream, uint32_t index);

pgp_error_t pgp_packet_stream_read(pgp_stream_t **stream, void *data, size_t size);
pgp_error_t pgp_packet_stream_write(pgp_stream_t *stream, void **buffer, size_t *size);
pgp_error_t pgp_packet_stream_read_armor(pgp_stream_t **stream, void *buffer, uint32_t buffer_size);
pgp_error_t pgp_packet_stream_write_armor(pgp_stream_t *stream, armor_options *options, void **buffer, size_t *size);

size_t pgp_packet_stream_octets(pgp_stream_t *stream);
size_t pgp_packet_stream_print(pgp_stream_t *stream, void *buffer, size_t size, uint16_t options);

pgp_stream_t *pgp_packet_stream_filter_padding_packets(pgp_stream_t *stream);
pgp_stream_t *pgp_packet_stream_filter_marker_packets(pgp_stream_t *stream);
pgp_stream_t *pgp_packet_stream_filter_non_exportable_signatures(pgp_stream_t *stream);
pgp_stream_t *pgp_packet_stream_collate_partials(pgp_stream_t *stream);

pgp_error_t pgp_packet_stream_decompress(pgp_stream_t *stream);

#endif
