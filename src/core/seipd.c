/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <seipd.h>
#include <round.h>
#include <string.h>

pgp_sed_packet *pgp_sed_packet_read(pgp_sed_packet *packet, void *data, size_t size)
{
	// Copy the packet data.
	memcpy(packet->data, (byte_t *)data + packet->header.header_size, packet->header.body_size);

	return packet;
}

size_t pgp_sed_packet_write(pgp_sed_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// N bytes of symmetrically encryrpted data

	required_size = packet->header.header_size + packet->header.body_size;

	if (size < required_size)
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
