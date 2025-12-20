/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <os.h>
#include <status.h>

#include <buffer.h>
#include <print.h>
#include <scan.h>

#include <blake2.h>

#include <stdlib.h>
#include <string.h>

#define VALIDATE_BLAKE2B 1
#define VALIDATE_BLAKE2S 2

uint32_t blake2_validate(void *test, size_t size)
{
	buffer_t buffer = {.data = test, .size = size};
	byte_t line[2048] = {0};

	uint8_t validate_mode = 0;

	byte_t in[1024] = {0};
	byte_t key[1024] = {0};
	byte_t hash[64] = {0};
	byte_t check[64] = {0};

	size_t line_size = 0;
	uint32_t in_size = 0;
	uint32_t key_size = 0;
	uint32_t hash_size = 0;

	uint8_t in_fill = 0;
	uint8_t key_fill = 0;
	uint8_t hash_fill = 0;

	uint32_t total_count = 0;
	uint32_t fail_count = 0;

	while (pending(&buffer))
	{
		line_size = readline(&buffer, line, 2048);

		if (line_size == 0)
		{
			continue;
		}

		if (validate_mode == 0)
		{
			if (memcmp(line, "[BLAKE-2B]", 10) == 0)
			{
				validate_mode = VALIDATE_BLAKE2B;
			}

			if (memcmp(line, "[BLAKE-2S]", 10) == 0)
			{
				validate_mode = VALIDATE_BLAKE2S;
			}
		}

		if (memcmp(line, "in =", 4) == 0)
		{
			if (line_size - 4 > 0)
			{
				memcpy(in, line + 5, line_size - 5);
				in_size = line_size - 5;
			}

			in_fill = 1;
		}

		if (memcmp(line, "key =", 5) == 0)
		{
			if (line_size - 5 > 0)
			{
				memcpy(key, line + 6, line_size - 6);
				key_size = line_size - 6;
			}

			key_fill = 1;
		}

		if (memcmp(line, "hash =", 6) == 0)
		{
			if (line_size - 6 > 0)
			{
				memcpy(hash, line + 7, line_size - 7);
				hash_size = line_size - 7;
			}

			hash_fill = 1;
		}

		if (in_fill && key_fill && hash_fill)
		{
			if (validate_mode == VALIDATE_BLAKE2B)
			{
				blake2b_ctx ctx = {0};
				blake2b_param param = BLAKE2_PARAM_INIT(hash_size, key_size);

				blake2b_init(&ctx, &param, key);
				blake2b_update(&ctx, in, in_size);
				blake2b_final(&ctx, check, 64);

				if (memcmp(check, hash, hash_size) != 0)
				{
					fail_count += 1;
				}
			}

			if (validate_mode == VALIDATE_BLAKE2S)
			{
				blake2s_ctx ctx = {0};
				blake2s_param param = BLAKE2_PARAM_INIT(hash_size, key_size);

				blake2s_init(&ctx, &param, key);
				blake2s_update(&ctx, in, in_size);
				blake2s_final(&ctx, check, 64);

				if (memcmp(check, hash, hash_size) != 0)
				{
					fail_count += 1;
				}
			}

			memset(in, 0, 1024);
			memset(key, 0, 1024);
			memset(hash, 0, 64);
			memset(check, 0, 64);

			in_size = 0;
			key_size = 0;
			hash_size = 0;

			in_fill = 0;
			key_fill = 0;
			hash_fill = 0;

			total_count += 1;
		}

		memset(line, 0, 2048);
	}

	return fail_count != 0;
}

int main(int argc, char **argv)
{
	handle_t handle = 0;
	stat_t stat = {0};

	char *file = NULL;
	void *buffer = NULL;
	size_t size = 0;

	if (argc != 2)
	{
		return 1;
	}

	file = argv[1];
	size = strnlen(file, 65536);

	os_stat(0, file, size, 0, &stat, sizeof(stat_t));
	os_open(&handle, 0, file, size, FILE_ACCESS_READ, 0, 0);

	buffer = malloc(stat.st_size);

	if (buffer == NULL)
	{
		return 1;
	}

	size = 0;

	os_read(handle, buffer, stat.st_size, &size);
	os_close(handle);

	return blake2_validate(buffer, size);
}
