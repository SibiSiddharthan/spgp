/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <os.h>

#include <packet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

pgp_stream_t *spgp_preprocess_stream(pgp_stream_t *stream)
{
	// First collate any partials
	// PGP_CALL(pgp_packet_stream_collate_partials(stream));

	// Decompress any compressed packets in the stream
	PGP_CALL(pgp_packet_stream_decompress(stream));

	// Collate partials again
	// PGP_CALL(pgp_packet_stream_collate_partials(stream));

	// Filter out padding and marker packets
	pgp_packet_stream_filter_padding_packets(stream);

	return stream;
}
