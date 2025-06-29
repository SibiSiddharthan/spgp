/*
   Copyright (c) 2024-2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <os.h>
#include <errno.h>

#include <status.h>

status_t _os_status(errno_t error)
{
	switch (error)
	{
	case 0:
		return OS_STATUS_SUCCESS;

	case ENOMEM:
		return OS_STATUS_NO_ACCESS;

	case EACCES:
		return OS_STATUS_NO_ACCESS;

	case EPERM:
		return OS_STATUS_NO_PERMISSION;

	case ENOENT:
		return OS_STATUS_PATH_NOT_FOUND;

	case ENAMETOOLONG:
		return OS_STATUS_NAME_TOO_LONG;

	case ENOTDIR:
		return OS_STATUS_NOT_DIRECTORY;

	case ENOTEMPTY:
		return OS_STATUS_DIRECTORY_NOT_EMPTY;

	case EEXIST:
		return OS_STATUS_PATH_EXISTS;

	case EBADF:
		return OS_STATUS_INVALID_HANDLE;

	case EIO:
		return OS_STATUS_IO_ERROR;

	case EINVAL:
		return OS_STATUS_INVALID_PARAMETER;

	case EISDIR:
		return OS_STATUS_IS_DIRECTORY;

	case EPIPE:
		return OS_STATUS_PIPE_ERROR;

	case ENOTSUP:
		return OS_STATUS_NOT_SUPPORTED;

	case E2BIG:
		return OS_STATUS_TOO_BIG;

	default:
		return OS_STATUS_UNKNOWN;
	};
}
