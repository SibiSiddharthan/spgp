/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <print.h>
#include <buffer.h>

#include <stdlib.h>

#include "varargs.h"

#define PRINT_ALTERNATE_FORM 0x01 // '#'
#define PRINT_ZERO_PADDED    0x02 // '0'
#define PRINT_SPACE_PADDED   0x04 // ' '
#define PRINT_LEFT_JUSTIFY   0x08 // '-'
#define PRINT_FORCE_SIGN     0x10 // '+'
#define PRINT_UPPER_CASE     0x20 // 'X|G|A|E'
#define PRINT_GROUP_DIGITS   0x40 // '''

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

	PRINT_CHAR,
	PRINT_STRING,

	PRINT_POINTER,
	PRINT_RESULT,

} print_type;

typedef enum _print_modifier
{
	PRINT_MOD_NONE = 0,

	PRINT_MOD_INT16,
	PRINT_MOD_INT64,
	PRINT_MOD_INT8,

	PRINT_MOD_U16CHAR,
	PRINT_MOD_U32CHAR,

	PRINT_MOD_U16STRING,
	PRINT_MOD_U32STRING,

} print_modifier;

typedef struct _print_config
{
	print_type type;
	print_modifier modifier;
	uint32_t flags;
	uint32_t width;
	uint32_t precision;
} print_config;

static uint32_t parse_print_specifier(const char *format)
{
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
