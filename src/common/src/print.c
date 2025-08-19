/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <print.h>
#include <buffer.h>

#include <stdlib.h>

typedef enum _print_type
{
	PRINT_INT_NUMBER = 1,

	PRINT_UINT_BINARY,
	PRINT_UINT_OCTAL,
	PRINT_UINT_HEX,
	PRINT_UINT_NUMBER,

	PRINT_DOUBLE_NORMAL,
	PRINT_DOUBLE_SCIENTIFIC,
	PRINT_DOUBLE_HEX,

	PRINT_U8CHAR,
	PRINT_U16CHAR,
	PRINT_U32CHAR,

	PRINT_U8STRING,
	PRINT_U16STRING,
	PRINT_U32STRING,

	PRINT_POINTER,
	PRINT_RESULT,

} print_type;

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
