/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_PRINT_H
#define TLS_PRINT_H

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#include <ptr.h>

static inline size_t print_format(uint32_t indent, void *str, size_t size, const char *format, ...)
{
	size_t pos = 0;

	va_list args;
	va_start(args, format);

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "%*s", indent * 4, "");
	pos += vsnprintf(PTR_OFFSET(str, pos), size - pos, format, args);

	va_end(args);

	return pos;
}

#endif
