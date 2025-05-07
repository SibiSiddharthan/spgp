/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <os.h>
#include <status.h>

char *os_status(status_t status)
{
	switch (status)
	{
	case OS_STATUS_SUCCESS:
		return "Success";
	case OS_STATUS_NO_PERMISSION:
		return "Not Enough Permissions";
	case OS_STATUS_PATH_NOT_FOUND:
		return "Path Not Found";
	case OS_STATUS_IO_ERROR:
		return "IO Error";
	case OS_STATUS_TOO_BIG:
		return "Too Large";
	case OS_STATUS_PENDING:
		return "Operation Is Pending";
	case OS_STATUS_INVALID_HANDLE:
		return "Bad Handle";
	case OS_STATUS_NO_MEMORY:
		return "Out Of Memory";
	case OS_STATUS_NO_ACCESS:
		return "Access Denied";
	case OS_STATUS_PATH_EXISTS:
		return "Path Already Exists";
	case OS_STATUS_NOT_DIRECTORY:
		return "Not A Directory";
	case OS_STATUS_IS_DIRECTORY:
		return "Is A Directory";
	case OS_STATUS_INVALID_PARAMETER:
		return "Invalid Parameter";
	case OS_STATUS_TOO_MANY_FILES:
		return "Too Many Files";
	case OS_STATUS_NO_TTY:
		return "Not A Terminal Device";
	case OS_STATUS_NO_SPACE:
		return "Not Enough Space";
	case OS_STATUS_TOO_MANY_LINKS:
		return "Too Many Links";
	case OS_STATUS_PIPE_ERROR:
		return "Pipe Error";
	case OS_STATUS_NAME_TOO_LONG:
		return "Path Name Too Long";
	case OS_STATUS_NOT_LOCKED:
		return "File Not Locked";
	case OS_STATUS_INVALID_SYSCALL:
		return "Unknown Syscall";
	case OS_STATUS_DIRECTORY_NOT_EMPTY:
		return "Directory Not Empty";
	case OS_STATUS_END_OF_DATA:
		return "End Of Data";
	case OS_STATUS_NOT_SUPPORTED:
		return "Operation Not Supported";
	case OS_STATUS_TIMED_OUT:
		return "Operation Timed Out";
	}

	return "Unknown";
}