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

		// Move the armor packet to the beginning of the stream
		if (command.print_armor_info)
		{
			pgp_packet_header *header = NULL;
			uint32_t start = 0;

			for (uint32_t j = 0; j < stream->count; ++j)
			{
				header = stream->packets[i];

				if (pgp_packet_type_from_tag(header->tag) == PGP_ARMOR)
				{
					pgp_stream_insert(stream, pgp_stream_remove(stream, j), start);
					start = j + 1;
				}
			}
		}

		pgp_packet_stream_print(stream, str, 65536, options);
		pgp_stream_delete(stream, pgp_packet_delete);
		printf("%s", str);
	}
}
