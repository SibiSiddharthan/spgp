/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <print.h>

#include <x509/oid.h>

int main(int argc, char **argv)
{
	byte_t buffer[256] = {0};
	char string[256] = {0};

	uint32_t result = 0;

	if (argc != 2)
	{
		printf("Invalid Usage.\n");
		return 1;
	}

	result = oid_encode(buffer, 256, argv[1], strlen(argv[1]));

	if (result == 0)
	{
		printf("Invalid OID.\n");
		return 1;
	}

	sprint(string, 256, "{%'A[%#^.2hhx]}", buffer, result);
	printf("%s\n", string);

	return 0;
}
