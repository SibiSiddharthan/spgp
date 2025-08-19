/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <print.h>
#include <buffer.h>

#include <stdlib.h>

static uint32_t parse_print_specifier(const char *format)
{
}

static uint32_t count_print_args(const char *format, va_list args)
{
	byte_t byte = 0;
	uint32_t count = 0;

	void **arg = NULL;

	while ((byte = *format++) != '\0')
	{
		if (byte == '%')
		{
			byte = *format++;

			if (byte == '\0')
			{
				break;
			}

			if (byte == '%')
			{
				continue;
			}

			count += 1;
		}
	}

	arg = malloc(count * sizeof(void *));

	for (uint32_t i = 0; i < count; ++i)
	{
		arg[i] = va_arg(args, void *);
	}

	return count;
}

uint32_t vxprint(buffer_t *buffer, const char *format, va_list args)
{
	uint32_t result = 0;
	byte_t byte = 0;

	while ((byte = *format++) != '\0')
	{
		if (byte == '%')
		{
			byte = *format++;

			if (byte == '\0')
			{
				break;
			}

			if (byte == '%')
			{
				result += writebyte(buffer, '%');
				continue;
			}

			while ((byte = *format++) != '\0')
			{

				// ll and hh
				if (byte == 'l' || byte == 'h')
				{
				}
			}

			continue;
		}

		result += writebyte(buffer, byte);
	}

	return result;
}
