/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void make_output_filename(char buffer[256], char *filename)
{
	strncpy(buffer, filename, 256);
	strncat(buffer, ".pgp", 4);
}

void spgp_dearmor(void)
{
	pgp_stream_t *stream = NULL;
	char buffer[256] = {0};

	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		stream = spgp_read_pgp_packets(command.args->data[i]);

		if (command.args->data[i] == NULL)
		{
			spgp_write_pgp_packets(NULL, stream, NULL);
		}
		else
		{
			make_output_filename(buffer, command.args->data[i]);
			spgp_write_pgp_packets(buffer, stream, NULL);
		}
	}
}

void spgp_list_packets(void)
{
	pgp_stream_t *stream = NULL;

	char str[65536] = {0};
	uint16_t options = 0;

	if (command.list_packets == 1 && command.dump_packets == 0)
	{
		options |= PGP_PRINT_HEADER_ONLY;
	}

	if (command.no_print_mpis)
	{
		options |= PGP_PRINT_MPI_MINIMAL;
	}

	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		stream = spgp_read_pgp_packets(command.args->data[i]);

		// Remove the armor packets if we don't need it
		if (command.print_armor_info == 0)
		{
			stream = pgp_packet_stream_filter_marker_packets(stream);
		}

		if (stream->count == 0)
		{
			return;
		}

		pgp_packet_stream_print(stream, str, 65536, options);
		pgp_stream_delete(stream, pgp_packet_delete);
		printf("%s", str);
	}
}
