/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <win32/nt.h>
#include <win32/io.h>

status_t os_close(handle_t handle)
{
	return NtClose(handle);
}

status_t os_read(handle_t handle, void *buffer, size_t size, size_t *result)
{
	NTSTATUS status;
	IO_STATUS_BLOCK io = {0};

	if (buffer == NULL)
	{
		return -1;
	}

	status = NtReadFile(handle, NULL, NULL, NULL, &io, buffer, (ULONG)size, NULL, NULL);

	if (status > 0)
	{
		*result = io.Information;
	}

	return status;
}

status_t os_write(handle_t handle, void *buffer, size_t size, size_t *result)
{
	NTSTATUS status;
	IO_STATUS_BLOCK io = {0};
	LARGE_INTEGER offset = {0};

	if (buffer == NULL)
	{
		return -1;
	}

	offset.HighPart = -1;
	offset.LowPart = FILE_USE_FILE_POINTER_POSITION;

	status = NtWriteFile(handle, NULL, NULL, NULL, &io, buffer, (ULONG)size, &offset, NULL);

	if (status > 0)
	{
		*result = io.Information;
	}

	return status;
}
