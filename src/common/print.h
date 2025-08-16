/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_PRINT_H
#define COMMON_PRINT_H

#include <stdarg.h>
#include <buffer.h>

uint32_t vxprint(buffer_t *buffer, const char *format, va_list args);

static inline uint32_t vsprint(void *buffer, uint32_t size, const char *format, va_list args)
{
	return vxprint(&(buffer_t){.data = buffer, .size = size}, format, args);
}

static inline uint32_t sprint(void *buffer, uint32_t size, const char *format, ...)
{
	uint32_t result = 0;
	va_list args = NULL;

	va_start(args, format);
	result = vsprint(buffer, size, format, args);
	va_end(args);

	return result;
}

static inline uint32_t xprint(buffer_t *buffer, const char *format, ...)
{
	uint32_t result = 0;
	va_list args = NULL;

	va_start(args, format);
	result = vxprint(buffer, format, args);
	va_end(args);

	return result;
}

#endif
