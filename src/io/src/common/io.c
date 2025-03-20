/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <io.h>
#include <status.h>

#include <minmax.h>
#include <round.h>
#include <ptr.h>

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

status_t file_open(file_t *file, handle_t root, const char *path, uint16_t length, uint32_t flags, uint32_t allocation)
{
	status_t status = 0;
	handle_t handle = 0;
	uint32_t access = 0;
	uint32_t options = 0;

	memset(file, 0, sizeof(file_t));

	allocation = ROUND_UP(MAX(allocation, 1), 4096); // 4KB

	// Take root as handle
	if (path == NULL || length == 0)
	{
		file->handle = root;
		goto buffer_allocate;
	}

	// Determine access and options
	switch (flags & (FILE_READ | FILE_WRITE | FILE_APPEND))
	{
	case 0x0:
		return OS_STATUS_INVALID_PARAMETER;
	case FILE_READ:
		access = FILE_ACCESS_READ;
		break;
	case FILE_WRITE:
		access = FILE_ACCESS_WRITE;
		options = FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE;
		break;
	case FILE_READ | FILE_WRITE:
		access = FILE_ACCESS_READ | FILE_ACCESS_WRITE;
		options = FILE_FLAG_CREATE;
		break;
	case FILE_APPEND:
	case FILE_WRITE | FILE_APPEND:
		access = FILE_ACCESS_WRITE | FILE_ACCESS_APPEND;
		options = FILE_FLAG_CREATE;
		break;
	case FILE_READ | FILE_APPEND:
	case FILE_READ | FILE_WRITE | FILE_APPEND:
		access = FILE_ACCESS_READ | FILE_ACCESS_WRITE | FILE_ACCESS_APPEND;
		options = FILE_FLAG_CREATE;
		break;
	}

	status = os_open(&handle, root, path, length, access, options, 0700);

	if (status != OS_STATUS_SUCCESS)
	{
		return status;
	}

	file->status = status;
	file->handle = handle;

buffer_allocate:
	file->buffer = malloc(allocation);
	file->size = allocation;

	if (file->buffer == NULL)
	{
		if (handle != 0)
		{
			os_close(handle);
		}

		return OS_STATUS_NO_MEMORY;
	}

	memset(file->buffer, 0, allocation);

	return status;
}

status_t file_close(file_t *file)
{
	status_t status = 0;

	status = os_close(file->handle);

	if (status != OS_STATUS_SUCCESS)
	{
		return status;
	}

	// Free the buffer
	free(file->buffer);
	file->buffer = NULL;

	return status;
}

size_t file_read(file_t *file, void *buffer, size_t size)
{
	size_t result = 0;
	size_t direct = 0;

	// Copy the buffered data first
	if (file->remaining != 0)
	{
		size_t copy_size = MIN(size, file->remaining);

		memcpy(buffer, PTR_OFFSET(file->buffer, file->size - file->remaining), copy_size);

		file->pos += copy_size;
		file->remaining -= copy_size;
		result += copy_size;
	}

	if (result == size)
	{
		return result;
	}

	// Direct read (exclude last block)
	direct = ROUND_DOWN((size - result), file->size);

	if (direct != 0)
	{
		status_t status = 0;
		size_t read = 0;

		status = os_read(file->handle, PTR_OFFSET(buffer, result), direct, &read);

		if (status != OS_STATUS_SUCCESS)
		{
			file->status = status;
			return result;
		}

		file->pos += read;
		file->offset += read;
		result += read;
	}

	// Final read
	if (result < size)
	{
		status_t status = 0;
		size_t read = 0;
		size_t copy_size = 0;

		status = os_read(file->handle, file->buffer, file->size, &read);

		if (status != OS_STATUS_SUCCESS)
		{
			file->status = status;
			return result;
		}

		file->offset += read;
		file->remaining = read;
		copy_size = MIN(size - result, read);

		file->pos += copy_size;
		file->remaining -= copy_size;
		result += copy_size;
	}

	return result;
}

size_t file_write(file_t *file, void *buffer, size_t size)
{
	size_t result = 0;
	size_t direct = 0;

	// Fill the buffer first
	if (file->remaining != file->size)
	{
		status_t status = 0;
		size_t write = 0;
		size_t copy_size = MIN(size, file->size - file->remaining);

		memcpy(buffer, PTR_OFFSET(file->buffer, file->size - file->remaining), copy_size);

		file->pos += copy_size;
		file->remaining += copy_size;
		result += copy_size;

		// Do a write
		if (file->remaining == file->size)
		{
			status = os_write(file->handle, file->buffer, file->size, &write);

			if (status != OS_STATUS_SUCCESS)
			{
				file->status = status;
				return result;
			}

			file->remaining = 0;
		}
	}

	if (result == size)
	{
		return result;
	}

	// Direct writes (excluding last block)
	direct = ROUND_DOWN((size - result), file->size);

	if (direct != 0)
	{
		status_t status = 0;
		size_t write = 0;

		status = os_write(file->handle, PTR_OFFSET(buffer, result), direct, &write);

		if (status != OS_STATUS_SUCCESS)
		{
			file->status = status;
			return result;
		}

		file->pos += write;
		file->offset += write;
		result += write;
	}

	// Copy remaining to buffer
	if (result < size)
	{
		size_t copy_size = size - result;

		memcpy(file->buffer, PTR_OFFSET(buffer, result), copy_size);

		file->pos += copy_size;
		file->remaining += copy_size;
		result += copy_size;
	}

	return result;
}
