/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <os.h>
#include <status.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdint.h>
#include <stddef.h>

#include <unused.h>

status_t os_open(handle_t *handle, handle_t root, const char *path, uint16_t length, uint32_t access, uint32_t flags, uint32_t mode)
{
	UNUSED(length);

	*handle = openat(root, path, access | flags, mode);

	if (*handle < 0)
	{
		return _os_status(errno);
	}

	return OS_STATUS_SUCCESS;
}

status_t os_close(handle_t handle)
{
	if (close(handle) < 0)
	{
		return _os_status(errno);
	}

	return OS_STATUS_SUCCESS;
}

status_t os_read(handle_t handle, void *buffer, size_t size, size_t *result)
{
	ssize_t read_result = 0;

	read_result = read(handle, buffer, size);

	if (read_result < 0)
	{
		return _os_status(errno);
	}

	*result = (size_t)read_result;

	return OS_STATUS_SUCCESS;
}

status_t os_write(handle_t handle, void *buffer, size_t size, size_t *result)
{
	ssize_t write_result = 0;

	write_result = write(handle, buffer, size);

	if (write_result < 0)
	{
		return _os_status(errno);
	}

	*result = (size_t)write_result;

	return OS_STATUS_SUCCESS;
}

status_t os_seek(handle_t handle, off_t offset, uint32_t whence)
{
	off_t offset = 0;

	offset = lseek(handle, offset, whence);

	if (offset < 0)
	{
		return _os_status(errno);
	}

	return OS_STATUS_SUCCESS;
}

status_t os_truncate(handle_t root, const char *path, uint16_t length, size_t size)
{
	int fd = 0;

	UNUSED(length);

	if ((fd = openat(root, path, 0, 0)) < 0)
	{
		return _os_status(errno);
	}

	if (ftrucate(fd, size) < 0)
	{
		close(fd);
		return _os_status(errno);
	}

	close(fd);

	return OS_STATUS_SUCCESS;
}

status_t os_mkdir(handle_t root, const char *path, uint16_t length, uint32_t mode)
{
	UNUSED(length);

	if (mkdirat(root, path, mode) < 0)
	{
		return _os_status(errno);
	}

	return OS_STATUS_SUCCESS;
}

status_t os_remove(handle_t root, const char *path, uint16_t length)
{
	UNUSED(length);

	if (unlinkat(root, path, 0) < 0)
	{
		if (errno = EISDIR)
		{
			if (unlinkat(root, path, 1) < 0)
			{
				return _os_status(errno);
			}

			errno = 0;
		}
	}

	return OS_STATUS_SUCCESS;
}

status_t os_isatty(handle_t handle, uint32_t *result)
{
	if (isatty(handle) == 1)
	{
		*result = 1;
		return OS_STATUS_SUCCESS;
	}
	else
	{
		*result = 0;
		return _os_status(errno);
	}
}
