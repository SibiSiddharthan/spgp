/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <win32/nt.h>
#include <win32/os.h>

#include <stdint.h>
#include <stddef.h>

status_t os_open(handle_t *handle, handle_t root, const char *path, uint16_t length, uint32_t access, uint32_t flags, uint32_t mode)
{
	NTSTATUS status = 0;
	IO_STATUS_BLOCK io = {0};
	OBJECT_ATTRIBUTES object = {0};
	UTF8_STRING u8_string = {.Buffer = (char *)path, .Length = length, .MaximumLength = length};
	UNICODE_STRING u16_string = {0};

	ACCESS_MASK access_rights = access;
	ULONG disposition = flags & (FILE_FLAG_CREATE | FILE_FLAG_EXCLUSIVE | FILE_FLAG_TRUNCATE);
	ULONG share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	ULONG attributes = flags & (FILE_FLAG_READONLY | FILE_FLAG_HIDDEN | FILE_FLAG_SYSTEM);
	ULONG options =
		((flags & (FILE_FLAG_DIRECTORY | FILE_FLAG_SYNC | FILE_FLAG_DIRECT | FILE_FLAG_NON_DIRECTORY | FILE_FLAG_NOFOLLOW)) >> 1) |
		(flags & FILE_FLAG_NONBLOCK ? 0 : FILE_SYNCHRONOUS_IO_NONALERT);

	// Determine disposition
	switch (disposition)
	{
	case 0x0:
	case FILE_FLAG_EXCLUSIVE:
		disposition = FILE_OPEN;
		break;
	case FILE_FLAG_CREATE:
		disposition = FILE_OPEN_IF;
		break;
	case FILE_FLAG_TRUNCATE:
	case FILE_FLAG_TRUNCATE | FILE_FLAG_EXCLUSIVE:
		disposition = FILE_OVERWRITE;
		break;
	case FILE_FLAG_CREATE | FILE_FLAG_EXCLUSIVE:
	case FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE | FILE_FLAG_EXCLUSIVE:
		disposition = FILE_CREATE;
		break;
	case FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE:
		disposition = FILE_OVERWRITE_IF;
		break;
	}

	RtlUTF8StringToUnicodeString(&u16_string, &u8_string, TRUE);

	InitializeObjectAttributes(&object, &u16_string, OBJ_CASE_INSENSITIVE | (flags & FILE_FLAG_NO_INHERIT ? 0 : OBJ_INHERIT), root, NULL);

	status = NtCreateFile(handle, access_rights, &object, &io, NULL, attributes, share, disposition, options, NULL, 0);
	RtlFreeUnicodeString(&u16_string);

	return status;
}

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

status_t os_mkdir(handle_t root, const char *path, uint16_t length, uint32_t mode)
{
	NTSTATUS status = 0;
	HANDLE handle = 0;
	IO_STATUS_BLOCK io = {0};
	OBJECT_ATTRIBUTES object = {0};
	UTF8_STRING u8_string = {.Buffer = (char *)path, .Length = length, .MaximumLength = length};
	UNICODE_STRING u16_string = {0};

	RtlUTF8StringToUnicodeString(&u16_string, &u8_string, TRUE);

	InitializeObjectAttributes(&object, &u16_string, OBJ_CASE_INSENSITIVE, root, NULL);

	status = NtCreateFile(&handle, FILE_READ_ATTRIBUTES, &object, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						  FILE_CREATE, FILE_DIRECTORY_FILE, NULL, 0);

	RtlFreeUnicodeString(&u16_string);

	if (status > 0)
	{
		NtClose(handle);
	}

	return status;
}
