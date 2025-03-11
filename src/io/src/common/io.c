/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <io.h>

#include <stdlib.h>
#include <string.h>

status_t dir_open(dir_t *directory, handle_t root, const char *path, uint16_t length)
{
	status_t status = 0;
	handle_t handle = 0;
	size_t size = 1u << 16;

	status = os_open(&handle, root, path, length, FILE_ACCESS_READ, FILE_FLAG_DIRECTORY, 0);

	if (status < 0)
	{
		return status;
	}

	memset(directory, 0, sizeof(dir_t));

	directory->status = status;
	directory->handle = handle;

	directory->buffer = malloc(size);
	directory->size = size;

	if (directory->buffer == NULL)
	{
		return 0;
	}

	memset(directory->buffer, 0, size);

	return status;
}

status_t dir_close(dir_t *directory)
{
	status_t status = 0;

	status = os_close(directory->handle);

	if (status < 0)
	{
		return status;
	}

	// Free the buffer
	free(directory->buffer);
	directory->buffer = NULL;

	return status;
}
