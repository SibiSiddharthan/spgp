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

uint32_t spgp_list_packets(spgp_command *command)
{
	void *buffer = NULL;
	size_t size = 0;

	char str[65536] = {0};
	uint16_t options = 0;

	buffer = spgp_read_file(command->list_packets.file, SPGP_STD_INPUT, &size);

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

	free(buffer);

	return 0;
}
