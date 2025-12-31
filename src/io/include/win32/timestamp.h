/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef OS_WIN32_TIMESTAMP_H
#define OS_WIN32_TIMESTAMP_H

#include <win32/types.h>
#include <win32/nt.h>

static inline timespec_t _os_time_to_timespec(LARGE_INTEGER LT)
{
	struct timespec result = {0};
	time_t epoch = LT.QuadPart - (uint64_t)116444736000000000;

	result.tv_sec = epoch / 10000000;
	result.tv_nsec = (epoch % 10000000) * 100;

	return result;
}

#endif
