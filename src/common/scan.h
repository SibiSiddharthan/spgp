/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_SCAN_H
#define COMMON_SCAN_H

#include <stdarg.h>
#include <buffer.h>

uint32_t vxscan(buffer_t *buffer, const char *format, va_list args);

static inline uint32_t vsscan(void *buffer, uint32_t size, const char *format, va_list args)
{
	return vxscan(&(buffer_t){.data = buffer, .size = size}, format, args);
}

static inline uint32_t sscan(void *buffer, uint32_t size, const char *format, ...)
{
	uint32_t result = 0;
	va_list args = NULL;

	va_start(args, format);
	result = vsscan(buffer, size, format, args);
	va_end(args);

	return result;
}

static inline uint32_t xscan(buffer_t *buffer, const char *format, ...)
{
	uint32_t result = 0;
	va_list args = NULL;

	va_start(args, format);
	result = vxscan(buffer, format, args);
	va_end(args);

	return result;
}

#endif
