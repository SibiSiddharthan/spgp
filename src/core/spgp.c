/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <spgp.h>
#include <packet.h>

#include <stdio.h>

int main(int argc, char **argv)
{
	char buffer[65536];
	size_t size = 0;

	for (int i = 1; i < argc; ++i)
	{
		FILE *file = fopen(argv[i], "rb");

		if (file == NULL)
		{
			printf("%s not found.\n", argv[i]);
			break;
		}

		size = fread(buffer, 1, 65536, file);
		fclose(file);
	}

	return 0;
}
