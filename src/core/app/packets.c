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

	if (command.args != NULL)
	{
		for (uint32_t i = 0; i < command.args->count; ++i)
		{
			stream = spgp_read_pgp_packets(command.args->packets[i]);

			pgp_packet_stream_print(stream, str, 65536, options);
			printf("%s\n", str);
		}
	}
	else
	{
		stream = spgp_read_pgp_packets(NULL);

		pgp_packet_stream_print(stream, str, 65536, options);
		printf("%s\n", str);
	}
}
