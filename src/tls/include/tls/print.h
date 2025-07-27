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

static const char hex_lower_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

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

static inline uint32_t print_hex(void *buffer, void *data, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	for (uint32_t i = 0; i < size; ++i)
	{
		uint8_t a, b;

		a = ((uint8_t *)data)[i] / 16;
		b = ((uint8_t *)data)[i] % 16;

		out[pos++] = hex_lower_table[a];
		out[pos++] = hex_lower_table[b];
	}

	out[pos++] = '\n';

	return pos;
}

static inline uint32_t print_bytes(uint32_t indent, void *buffer, uint32_t buffer_size, char *prefix, void *data, uint32_t data_size)
{
	uint32_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(buffer, pos), buffer_size, "%s (%u bytes): ", prefix, data_size);
	pos += print_hex(PTR_OFFSET(buffer, pos), data, data_size);

	return pos;
}

#endif
