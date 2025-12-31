/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_PRINT_H
#define TLS_PRINT_H

#include <stdarg.h>
#include <stdint.h>

#include <print.h>
#include <ptr.h>

#include <tls/algorithms.h>
#include <tls/grease.h>

static inline size_t print_indent(buffer_t *buffer, uint32_t indent)
{
	return xprint(buffer, "%*s", indent * 4, "");
}

static inline size_t print_format(buffer_t *buffer, uint32_t indent, const char *format, ...)
{
	size_t pos = 0;

	va_list args;
	va_start(args, format);

	pos += print_indent(buffer, indent);
	pos += vxprint(buffer, format, args);

	va_end(args);

	return pos;
}

static inline uint32_t print_bytes(void *buffer, uint32_t indent, char *prefix, void *data, uint32_t size)
{
	return print_format(buffer, indent, "%1$s (%3$u bytes): %2$.*3$R\n", prefix, data, size);
}


#endif
