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
	pgp_stream_t *stream = NULL;

	char str[65536] = {0};
	uint16_t options = 0;

	stream = spgp_read_pgp_packets(command->list_packets.file, SPGP_STD_INPUT);

	if (command->list_packets.dump == 0)
	{
		options |= PGP_PRINT_HEADER_ONLY;
	}

	if (command->list_packets.no_mpi)
	{
		options |= PGP_PRINT_MPI_MINIMAL;
	}

	pgp_stream_print(stream, str, 65536, options);
	printf("%s", str);

	return 0;
}
