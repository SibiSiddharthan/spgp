/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <hash.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

byte_t hex_value(char ch)
{
	switch (ch)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'a':
		return 10;
	case 'b':
		return 11;
	case 'c':
		return 12;
	case 'd':
		return 13;
	case 'e':
		return 14;
	case 'f':
		return 15;
	}

	return 255;
}

void hex_to_block(byte_t *block, size_t size, char *hex)
{
	uint64_t i = 0, j = 0;

	for (i = 0; i < (size * 2) && j < size; i += 2)
	{
		block[j++] = hex_value(hex[i]) * 16 + hex_value(hex[i + 1]);
	}
}

static void get_message(void *message, size_t size)
{
	size_t length = size * 2;
}

static int process_file(void *buffer, size_t size)
{
	size_t count = 0;
	size_t fail = 0;
	size_t pos = 0;

	size_t length = 0;
	char *in = buffer;
	char message[65536] = {0};

	while (pos < size)
	{
		void *off = memchr(PTR_OFFSET(buffer, pos), '\n', size - pos);

		if (off == NULL)
		{
			return fail;
		}

		if (in[pos] == '#')
		{
			// Skip line
			pos = ((uintptr_t)off - (uintptr_t)buffer) + 1;
		}

		if (in[pos] == '[')
		{
			// Skip line
			pos = ((uintptr_t)off - (uintptr_t)buffer) + 1;
		}

		if (in[pos] == 'L' && in[pos + 1] == 'L' && in[pos + 2] == 'L')
		{
			// Skip line
			pos = ((uintptr_t)off - (uintptr_t)buffer) + 1;
		}
	}

	hex_to_block(message, length, NULL);
}

int main(int argc, char **argv)
{
	int status = 0;

	FILE *file = NULL;
	void *buffer = NULL;
	size_t size = 0;

	if (argc != 2)
	{
		printf("hash-validate [file]\n");
		return 1;
	}

	file = fopen(argv[1], "rb");

	if (file == NULL)
	{
		printf("Unable to open file %s\n", argv[1]);
		return 1;
	}

	buffer = malloc(1u << 24);
	memset(buffer, 0, 1u << 24);

	size = fread(buffer, 1, 1u << 24, file);

	status = process_file(buffer, size);

	free(buffer);
	fclose(file);

	return status;
}