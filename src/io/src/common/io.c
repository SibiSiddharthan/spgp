/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <io.h>
#include <status.h>

#include <round.h>

#include <stdlib.h>
#include <string.h>

status_t dir_open(dir_t *directory, handle_t root, const char *path, uint16_t length)
{
	status_t status = 0;
	handle_t handle = 0;
	size_t size = 1u << 16;

	memset(directory, 0, sizeof(dir_t));

	// Take root as handle
	if (path == NULL || length == 0)
	{
		directory->handle = root;
		goto buffer_allocate;
	}

	status = os_open(&handle, root, path, length, FILE_ACCESS_READ, FILE_FLAG_DIRECTORY, 0);

	if (status != OS_STATUS_SUCCESS)
	{
		return status;
	}

	directory->status = status;
	directory->handle = handle;

buffer_allocate:
	directory->buffer = malloc(size);
	directory->size = size;

	if (directory->buffer == NULL)
	{
		if (handle != 0)
		{
			os_close(handle);
		}

		return OS_STATUS_NO_MEMORY;
	}

	memset(directory->buffer, 0, size);

	return status;
}

status_t dir_close(dir_t *directory)
{
	status_t status = 0;

	status = os_close(directory->handle);

	if (status != OS_STATUS_SUCCESS)
	{
		return status;
	}

	// Free the buffer
	free(directory->buffer);
	directory->buffer = NULL;

	return status;
}
