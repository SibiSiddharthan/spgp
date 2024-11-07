/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>

#include "packet.h"

int main(int argc, char **argv)
{
	char buffer[65536] = {0};
	size_t size = 0;

	const char *filename = "test.c.sig";

	FILE *f = fopen(filename, "rb");
	size = fread(buffer, 1, 65536, f);

	dump_pgp_packet(buffer, size);

	return 0;
}
