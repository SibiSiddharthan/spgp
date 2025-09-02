/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <scan.h>
#include <buffer.h>

#include "convert.h"
#include "varargs.h"

// Flags
#define SCAN_ALLOC_STRING 1 // m

// Modifiers
#define SCAN_MOD_NONE        0
#define SCAN_MOD_SHORT_SHORT 1 // hh
#define SCAN_MOD_SHORT       2 // h
#define SCAN_MOD_LONG        3 // l
#define SCAN_MOD_LONG_LONG   4 // ll

#define SCAN_MOD_MAX     5 // j
#define SCAN_MOD_SIZE    6 // z
#define SCAN_MOD_PTRDIFF 7 // t

#define PRINT_MOD_LONG_DOUBLE 8

typedef enum _scan_type
{
	SCAN_INT_NUMBER = 1,

	SCAN_UINT_BINARY,
	SCAN_UINT_OCTAL,
	SCAN_UINT_HEX,
	SCAN_UINT_NUMBER,

	SCAN_DOUBLE_NORMAL,
	SCAN_DOUBLE_HEX,
	SCAN_DOUBLE_SCIENTIFIC,
	SCAN_DOUBLE_SCIENTIFIC_SHORT,

	SCAN_CHAR,
	SCAN_STRING,

	SCAN_POINTER,
	SCAN_RESULT,

	SCAN_UNKNOWN

} scan_type;

uint32_t vxscan(buffer_t *buffer, const char *format, va_list list)
{
	variadic_args args = {0};
	buffer_t in = {.data = (void *)format, .pos = 0, .size = strnlen(format, 65536)};

	uint32_t result = 0;
	byte_t byte = 0;
	size_t pos = 0;

	variadic_args_init(&args, list);

	while ((byte = readbyte(&in)) != '\0')
	{
		if (byte == '%')
		{
			byte = peekbyte(&in, 0);

			if (byte == '\0')
			{
				break;
			}

			if (byte == '%')
			{
				readbyte(&in);
				continue;
			}

			continue;
		}
	}

	variadic_args_free(&args);

	return result;
}
