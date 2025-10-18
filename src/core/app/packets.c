/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <pgp/packet.h>

void spgp_dearmor(void)
{
	pgp_stream_t *stream = NULL;

	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		stream = spgp_read_pgp_packets(command.args->data[i]);
		stream = pgp_packet_stream_filter_armor_packets(stream);

		if (command.output != NULL)
		{
			spgp_write_pgp_packets(command.output, NULL, stream, NULL);
		}
		else
		{
			spgp_write_pgp_packets(command.args->data[i], SPGP_FILE_EXT, stream, NULL);
		}
	}
}

void spgp_list_packets(void)
{
	pgp_stream_t *stream = NULL;
	buffer_t buffer = {0};
	uint16_t options = 0;
	size_t result = 0;

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
			stream = pgp_packet_stream_filter_armor_packets(stream);
		}

		if (stream->count == 0)
		{
			return;
		}

		memory_buffer_init(&buffer, 4096);

		pgp_packet_stream_print(stream, &buffer, 0, options);
		pgp_stream_delete(stream, pgp_packet_delete);

		OS_CALL(os_write(STDOUT_HANDLE, buffer.data, buffer.size, &result), printf("Unable to write to stdout"));

		memory_buffer_free(&buffer);
	}
}
