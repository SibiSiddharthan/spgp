/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <scan.h>
#include <buffer.h>

#include "convert.h"
#include "varargs.h"

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
