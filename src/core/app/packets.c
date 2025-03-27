/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>

#include <stdio.h>
#include <string.h>

uint32_t spgp_list_packets(spgp_command *command)
{
	char buffer[65536] = {0};
	char str[65536] = {0};
	uint16_t options = 0;

	status_t status = 0;
	file_t file = {0};
	size_t size = 0;

	if (command->list_packets.file != NULL)
	{
		status = file_open(&file, HANDLE_CWD, command->list_packets.file, strlen(command->list_packets.file), FILE_READ, 65536);

		if (status != OS_STATUS_SUCCESS)
		{
			fprintf(stderr, "File not found: %s\n", command->list_packets.file);
			return 1;
		}

		size = file_read(&file, buffer, 65536);

		file_close(&file);
	}
	else
	{
		file_open(&file, STDIN_HANDLE, NULL, 0, FILE_READ, 65536);
		size = file_read(&file, buffer, 65536);
		file_close(&file);
	}

	if (command->list_packets.dump == 0)
	{
		options |= PGP_PRINT_HEADER_ONLY;
	}

	if (command->list_packets.no_mpi)
	{
		options |= PGP_PRINT_MPI_MINIMAL;
	}

	pgp_stream_t *stream = pgp_stream_read(buffer, size);
	pgp_stream_print(stream, str, 65536, options);

	printf("%s", str);

	return 0;
}
