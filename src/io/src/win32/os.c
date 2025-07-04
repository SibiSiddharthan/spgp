/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <win32/nt.h>
#include <win32/os.h>
#include <win32/timestamp.h>

#include <os.h>
#include <status.h>

#include <stdint.h>
#include <stddef.h>

static NTSTATUS _nt_open(HANDLE *handle, HANDLE root, CONST CHAR *path, USHORT length, ACCESS_MASK access, ULONG disposition, ULONG options)
{
	NTSTATUS status = 0;

	IO_STATUS_BLOCK io = {0};
	OBJECT_ATTRIBUTES object = {0};
	UNICODE_STRING *u16_path = NULL;

	if (path != NULL)
	{
		status = _os_ntpath((VOID **)&u16_path, root, path, length);

		if (status != STATUS_SUCCESS)
		{
			return _os_status(status);
		}

		// Full NT path, ignore root
		if (u16_path->Buffer[0] == L'\\')
		{
			root = NULL;
		}
	}

	InitializeObjectAttributes(&object, u16_path, OBJ_CASE_INSENSITIVE | OBJ_INHERIT, root, NULL);

	status = NtCreateFile(handle, access, &object, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disposition,
						  options, NULL, 0);

	RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_path);

	return status;
}

status_t os_open(handle_t *handle, handle_t root, const char *path, uint16_t length, uint32_t access, uint32_t flags, uint32_t mode)
{
	NTSTATUS status = 0;

	IO_STATUS_BLOCK io = {0};
	OBJECT_ATTRIBUTES object = {0};

	UNICODE_STRING *u16_path = NULL;
	PSECURITY_DESCRIPTOR security_descriptor = NULL;

	ACCESS_MASK access_rights = access | (flags & FILE_FLAG_APPEND);
	ULONG disposition = flags & (FILE_FLAG_CREATE | FILE_FLAG_EXCLUSIVE | FILE_FLAG_TRUNCATE);
	ULONG share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	ULONG attributes = flags & (FILE_FLAG_READONLY | FILE_FLAG_HIDDEN | FILE_FLAG_SYSTEM);
	ULONG options =
		((flags & (FILE_FLAG_DIRECTORY | FILE_FLAG_SYNC | FILE_FLAG_DIRECT | FILE_FLAG_NON_DIRECTORY | FILE_FLAG_NOFOLLOW)) >> 4) |
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

	if (path != NULL)
	{
		status = _os_ntpath((VOID **)&u16_path, root, path, length);

		if (status != STATUS_SUCCESS)
		{
			return _os_status(status);
		}

		// Full NT path, ignore root
		if (u16_path->Buffer[0] == L'\\')
		{
			root = NULL;
		}
	}

	if (flags & FILE_FLAG_CREATE)
	{
		security_descriptor = _os_security_descriptor(mode, (flags & FILE_FLAG_DIRECTORY));
	}

	InitializeObjectAttributes(&object, u16_path, OBJ_CASE_INSENSITIVE | (flags & FILE_FLAG_NO_INHERIT ? 0 : OBJ_INHERIT), root,
							   security_descriptor);

	status = NtCreateFile(handle, access_rights, &object, &io, NULL, attributes, share, disposition, options, NULL, 0);

	RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_path);
	RtlFreeHeap(NtCurrentProcessHeap(), 0, security_descriptor);

	return _os_status(status);
}

status_t os_close(handle_t handle)
{
	return _os_status(NtClose(handle));
}

status_t os_read(handle_t handle, void *buffer, size_t size, size_t *result)
{
	NTSTATUS status;
	IO_STATUS_BLOCK io = {0};

	status = NtReadFile(handle, NULL, NULL, NULL, &io, buffer, (ULONG)size, NULL, NULL);

	if (status != STATUS_SUCCESS && status != STATUS_PENDING && status != STATUS_END_OF_FILE && status != STATUS_PIPE_BROKEN &&
		status != STATUS_PIPE_EMPTY)
	{
		*result = 0;
	}
	else
	{
		*result = io.Information;
	}

	return _os_status(status);
}

status_t os_write(handle_t handle, void *buffer, size_t size, size_t *result)
{
	NTSTATUS status;
	IO_STATUS_BLOCK io = {0};
	LARGE_INTEGER offset = {0};

	offset.HighPart = -1;
	offset.LowPart = FILE_USE_FILE_POINTER_POSITION;

	status = NtWriteFile(handle, NULL, NULL, NULL, &io, buffer, (ULONG)size, &offset, NULL);

	if (status != STATUS_SUCCESS && status != STATUS_PENDING)
	{
		*result = 0;
	}
	else
	{
		*result = io.Information;
	}

	return _os_status(status);
}

status_t os_stat(handle_t root, const char *path, uint16_t length, uint32_t flags, void *buffer, uint16_t size)
{
	NTSTATUS status = 0;
	HANDLE handle = 0;
	IO_STATUS_BLOCK io = {0};

	FILE_FS_DEVICE_INFORMATION device_info = {0};

	if (size < sizeof(stat_t))
	{
		return OS_STATUS_INSUFFICIENT_BUFFER;
	}

	if (path != NULL)
	{
		status = _nt_open(&handle, root, path, length, FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, FILE_OPEN,
						  (flags & HANDLE_SYMLINK_NOFOLLOW) ? FILE_OPEN_REPARSE_POINT : 0);

		if (status != STATUS_SUCCESS)
		{
			return _os_status(status);
		}
	}
	else
	{
		handle = root;
	}

	stat_t *st = buffer;
	memset(st, 0, sizeof(stat_t));

	// This is important
	status = NtQueryVolumeInformationFile(handle, &io, &device_info, sizeof(FILE_FS_DEVICE_INFORMATION), FileFsDeviceInformation);

	if (status != STATUS_SUCCESS)
	{
		goto error;
	}

	DEVICE_TYPE type = device_info.DeviceType;

	if (type == FILE_DEVICE_DISK)
	{
		FILE_STAT_INFORMATION stat_info = {0};
		DWORD attributes = 0;

		status = NtQueryInformationFile(handle, &io, &stat_info, sizeof(FILE_STAT_INFORMATION), FileStatInformation);

		if (status != STATUS_SUCCESS)
		{
			goto error;
		}

		attributes = stat_info.FileAttributes;

		// Fill st_uid, st_gid, st_mode
		if ((flags & STAT_NO_ACLS) == 0)
		{
			_os_access(handle, st);
		}
		else
		{
			ACCESS_MASK access = stat_info.EffectiveAccess;

			if ((access & FILE_ACCESS_READ) == FILE_ACCESS_READ)
			{
				st->st_mode |= PERM_USER_READ;
			}
			if ((access & FILE_ACCESS_WRITE) == FILE_ACCESS_WRITE)
			{
				st->st_mode |= PERM_USER_WRITE;
			}
			if ((access & __FILE_ACCESS_EXECUTE) == __FILE_ACCESS_EXECUTE)
			{
				st->st_mode |= PERM_USER_EXECUTE;
			}
		}

		if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		{
			ULONG reparse_tag = stat_info.ReparseTag;
			if (reparse_tag == IO_REPARSE_TAG_SYMLINK || reparse_tag == IO_REPARSE_TAG_MOUNT_POINT)
			{
				st->st_mode |= STAT_FILE_TYPE_LINK;
			}
			if (reparse_tag == IO_REPARSE_TAG_AF_UNIX)
			{
				st->st_mode |= STAT_FILE_TYPE_SOCK;
			}
		}
		else if (attributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			st->st_mode |= STAT_FILE_TYPE_DIR;
		}
		else if ((attributes & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
								 FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_COMPRESSED |
								 FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_ENCRYPTED)) == 0)
		{
			st->st_mode |= STAT_FILE_TYPE_REG;
		}

		st->st_attributes = attributes & STAT_ATTRIBUTE_MASK;
		st->st_ino = stat_info.FileId.QuadPart;
		st->st_nlink = stat_info.NumberOfLinks;
		st->st_size = stat_info.EndOfFile.QuadPart;

		st->st_atim = _os_time_to_timespec(stat_info.LastAccessTime);
		st->st_mtim = _os_time_to_timespec(stat_info.LastWriteTime);
		st->st_ctim = _os_time_to_timespec(stat_info.ChangeTime);
		st->st_birthtim = _os_time_to_timespec(stat_info.CreationTime);

		if (STAT_IS_FIFO(st->st_mode))
		{
			PREPARSE_DATA_BUFFER reparse_buffer =
				(PREPARSE_DATA_BUFFER)RtlAllocateHeap(NtCurrentProcessHeap(), 0, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
			st->st_size = 0;

			if (reparse_buffer != NULL)
			{
				status = NtFsControlFile(handle, NULL, NULL, NULL, &io, FSCTL_GET_REPARSE_POINT, NULL, 0, reparse_buffer,
										 MAXIMUM_REPARSE_DATA_BUFFER_SIZE);

				if (status == STATUS_SUCCESS)
				{

					if (reparse_buffer->ReparseTag == IO_REPARSE_TAG_SYMLINK)
					{
						if (reparse_buffer->SymbolicLinkReparseBuffer.PrintNameLength != 0)
						{
							st->st_size = reparse_buffer->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR);
						}
						else if (reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameLength != 0)
						{
							st->st_size = reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR);
						}
					}

					if (reparse_buffer->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT)
					{
						if (reparse_buffer->MountPointReparseBuffer.PrintNameLength != 0)
						{
							st->st_size = reparse_buffer->MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR);
						}
						else if (reparse_buffer->MountPointReparseBuffer.SubstituteNameLength != 0)
						{
							st->st_size = reparse_buffer->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR);
						}
					}

					RtlFreeHeap(NtCurrentProcessHeap(), 0, reparse_buffer);
				}
				else
				{
					RtlFreeHeap(NtCurrentProcessHeap(), 0, reparse_buffer);
					goto error;
				}
			}
			else
			{
				goto error;
			}
		}
	}
	else if (type == FILE_DEVICE_NULL || type == FILE_DEVICE_CONSOLE)
	{
		st->st_mode = STAT_FILE_TYPE_CHAR | 0666;
		st->st_nlink = 1;
		st->st_rdev = 0;
		st->st_dev = 0;
	}
	else if (type == FILE_DEVICE_NAMED_PIPE)
	{
		st->st_mode = STAT_FILE_TYPE_FIFO;
		st->st_nlink = 1;
		st->st_rdev = 0;
		st->st_dev = 0;
	}

	return OS_STATUS_SUCCESS;

error:
	if (path != NULL)
	{
		NtClose(handle);
	}

	return _os_status(status);
}

status_t os_truncate(handle_t root, const char *path, uint16_t length, size_t size)
{
	NTSTATUS status = 0;
	HANDLE handle = 0;
	IO_STATUS_BLOCK io = {0};
	FILE_END_OF_FILE_INFORMATION eof = {0};

	if (path != NULL)
	{
		status = _nt_open(&handle, root, path, length, FILE_WRITE_DATA, FILE_OPEN, 0);

		if (status != STATUS_SUCCESS)
		{
			return _os_status(status);
		}
	}
	else
	{
		handle = root;
	}

	eof.EndOfFile.QuadPart = size;
	status = NtSetInformationFile(handle, &io, &eof, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);

	if (path != NULL)
	{
		NtClose(handle);
	}

	if (status != STATUS_SUCCESS)
	{
		_os_status(status);
	}

	return OS_STATUS_SUCCESS;
}

status_t os_seek(handle_t handle, off_t offset, uint32_t whence)
{
	NTSTATUS status = 0;
	IO_STATUS_BLOCK io = {0};
	FILE_POSITION_INFORMATION pos_info = {0};
	LONGLONG current_pos = 0;

	switch (whence)
	{
	case SEEK_BEGIN:
	{
		if (offset < 0)
		{
			return OS_STATUS_INVALID_PARAMETER;
		}

		current_pos = 0;
	}
	break;
	case SEEK_CURRENT:
	{
		FILE_POSITION_INFORMATION curpos_info = {0};

		status = NtQueryInformationFile(handle, &io, &curpos_info, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);
		current_pos = curpos_info.CurrentByteOffset.QuadPart;

		if (status != STATUS_SUCCESS)
		{
			return _os_status(status);
		}
	}
	break;
	case SEEK_END:
	{
		FILE_STANDARD_INFORMATION standard_info = {0};

		status = NtQueryInformationFile(handle, &io, &standard_info, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		current_pos = standard_info.EndOfFile.QuadPart;

		if (status != STATUS_SUCCESS)
		{
			return _os_status(status);
		}
	}
	break;
	}

	pos_info.CurrentByteOffset.QuadPart = current_pos + offset;
	status = NtSetInformationFile(handle, &io, &pos_info, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);

	return _os_status(status);
}

status_t os_mkdir(handle_t root, const char *path, uint16_t length, uint32_t mode)
{
	NTSTATUS status = 0;
	HANDLE handle = 0;

	IO_STATUS_BLOCK io = {0};
	OBJECT_ATTRIBUTES object = {0};

	UNICODE_STRING *u16_path = NULL;
	PSECURITY_DESCRIPTOR security_descriptor = _os_security_descriptor(mode, 1);

	status = _os_ntpath((VOID **)&u16_path, root, path, length);

	if (status != STATUS_SUCCESS)
	{
		goto finish;
	}

	// Full NT path, ignore root
	if (u16_path->Buffer[0] == L'\\')
	{
		root = NULL;
	}

	InitializeObjectAttributes(&object, u16_path, OBJ_CASE_INSENSITIVE, root, NULL);

	status = NtCreateFile(&handle, FILE_READ_ATTRIBUTES, &object, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						  FILE_CREATE, FILE_DIRECTORY_FILE, NULL, 0);

	if (status == STATUS_SUCCESS)
	{
		NtClose(handle);
	}

finish:
	RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_path);
	RtlFreeHeap(NtCurrentProcessHeap(), 0, security_descriptor);

	return _os_status(status);
}

status_t os_remove(handle_t root, const char *path, uint16_t length)
{
	NTSTATUS status = 0;
	HANDLE handle = 0;

	IO_STATUS_BLOCK io = {0};
	FILE_DISPOSITION_INFORMATION_EX dispostion = {0};

	status = _nt_open(&handle, root, path, length, DELETE, FILE_OPEN, FILE_OPEN_REPARSE_POINT);

	if (status != STATUS_SUCCESS)
	{
		return _os_status(status);
	}

	io.Status = 0;
	io.Information = 0;

	dispostion.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
	status = NtSetInformationFile(handle, &io, &dispostion, sizeof(FILE_DISPOSITION_INFORMATION_EX), FileDispositionInformationEx);
	NtClose(handle);

	return _os_status(status);
}

status_t os_lock(handle_t handle, size_t offset, size_t length, byte_t nonblocking, byte_t exclusive)
{
	NTSTATUS status = 0;
	IO_STATUS_BLOCK io = {0};

	status = NtLockFile(handle, NULL, NULL, NULL, &io, (LARGE_INTEGER *)&offset, (LARGE_INTEGER *)&length, 0, (nonblocking & 0x1),
						(exclusive & 0x1));

	return _os_status(status);
}

status_t os_unlock(handle_t handle, size_t offset, size_t length)
{
	NTSTATUS status = 0;
	IO_STATUS_BLOCK io = {0};

	status = NtUnlockFile(handle, &io, (LARGE_INTEGER *)&offset, (LARGE_INTEGER *)&length, 0);

	return _os_status(status);
}

status_t os_isatty(handle_t handle, uint32_t *result)
{
	NTSTATUS status = 0;
	IO_STATUS_BLOCK io = {0};
	FILE_FS_DEVICE_INFORMATION device_info = {0};

	status = NtQueryVolumeInformationFile(handle, &io, &device_info, sizeof(FILE_FS_DEVICE_INFORMATION), FileFsDeviceInformation);

	if (status != STATUS_SUCCESS)
	{
		*result = 0;
		return _os_status(status);
	}

	*result = device_info.DeviceType == FILE_DEVICE_CONSOLE ? 1 : 0;

	return OS_STATUS_SUCCESS;
}

handle_t _os_cwd_handle()
{
	return NtCurrentPeb()->ProcessParameters->CurrentDirectory.Handle;
}

handle_t _os_stdin_handle()
{
	return NtCurrentPeb()->ProcessParameters->StandardInput;
}

handle_t _os_stdout_handle()
{
	return NtCurrentPeb()->ProcessParameters->StandardOutput;
}

handle_t _os_stderr_handle()
{
	return NtCurrentPeb()->ProcessParameters->StandardError;
}
