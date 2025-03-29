/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <os.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static status_t spgp_read_disk_file(handle_t handle, size_t size, void **buffer, size_t *result)
{
	status_t status = 0;
	size_t read = 0;

	*buffer = malloc(size);

	if (*buffer == NULL)
	{
		return OS_STATUS_NO_MEMORY;
	}

	status = os_read(handle, buffer, size, &read);

	if (status != OS_STATUS_SUCCESS)
	{
		free(buffer);
	}

	*result = read;

	return status;
}

static status_t spgp_read_pipe_file(handle_t handle, void **buffer, size_t *result)
{
	status_t status = 0;
	size_t read = 0;
	size_t size = 0;

	size = 65536;
	*result = 0;
	*buffer = malloc(size);

	if (*buffer == NULL)
	{
		return OS_STATUS_NO_MEMORY;
	}

	while (1)
	{
		// Read in 64KB chunks
		status = os_read(handle, PTR_OFFSET(buffer, read), 65536, &read);

		*result += read;

		if (*result == size)
		{
			void *temp = NULL;

			size *= 2;
			temp = realloc(*buffer, size);

			if (temp == NULL)
			{
				free(buffer);
				return OS_STATUS_NO_MEMORY;
			}

			*buffer = temp;
		}

		if (status != OS_STATUS_SUCCESS)
		{
			if (status != OS_STATUS_END_OF_DATA)
			{
				free(buffer);
				return status;
			}

			status = OS_STATUS_SUCCESS;
			break;
		}
	}

	return status;
}

void *spgp_read_file(const char *file, uint32_t options, size_t *size)
{
	status_t status = 0;
	handle_t handle = 0;
	stat_t stat = {0};

	void *buffer = NULL;

	if (file != NULL)
	{
		status = os_open(&handle, HANDLE_CWD, file, strlen(file), FILE_ACCESS_READ, 0, 0);

		if (status != OS_STATUS_SUCCESS)
		{
			printf("Unable to open file %s.\n", file);
			exit(2);
		}

		status = os_stat(handle, NULL, 0, STAT_NO_ACLS, &stat, sizeof(stat_t));

		if (status != OS_STATUS_SUCCESS)
		{
			printf("Unable to stat file %s.\n", file);
			exit(2);
		}
	}
	else
	{
		if (options & SPGP_STD_INPUT)
		{
			handle = STDIN_HANDLE;
			status = os_stat(handle, NULL, 0, STAT_NO_ACLS, &stat, sizeof(stat_t));

			if (status != OS_STATUS_SUCCESS)
			{
				printf("Unable to stat file %s.\n", file);
				exit(2);
			}
		}
	}

	if (handle == 0)
	{
		exit(2);
	}

	if (STAT_IS_REG(stat.st_mode))
	{
		status = spgp_read_disk_file(handle, stat.st_size, &buffer, size);
	}
	else
	{
		status = spgp_read_pipe_file(handle, &buffer, size);
	}

	if (file != NULL)
	{
		os_close(handle);
	}

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to read file %s.\n", file);
		exit(2);
	}

	return buffer;
}

pgp_stream_t *spgp_read_pgp_packets(const char *file, uint32_t options)
{
	void *buffer = NULL;
	size_t size = 0;

	pgp_stream_t *stream = NULL;

	buffer = spgp_read_file(file, options, &size);
	stream = pgp_stream_read(buffer, size);

	if (stream == NULL)
	{
		printf("Invalid pgp stream.\n");
		exit(1);
	}

	return stream;
}
