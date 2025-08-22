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
	PRINT_DOUBLE_HEX,
	PRINT_DOUBLE_SCIENTIFIC,
	PRINT_DOUBLE_SCIENTIFIC_SHORT,

	PRINT_CHAR,
	PRINT_STRING,

	PRINT_POINTER,
	PRINT_RESULT,

	PRINT_UNKNOWN

} print_type;

typedef enum _print_modifier
{
	PRINT_MOD_NONE = 0,

	PRINT_MOD_SHORT_SHORT,
	PRINT_MOD_SHORT,
	PRINT_MOD_LONG,
	PRINT_MOD_LONG_LONG,

	PRINT_MOD_LONG_DOUBLE,

	PRINT_MOD_INTMAX,
	PRINT_MOD_SIZE,
	PRINT_MOD_PTRDIFF,
} print_modifier;

typedef struct _print_config
{
	print_type type;
	print_modifier modifier;
	uint32_t flags;
	uint32_t width;
	uint32_t precision;
} print_config;

static uint32_t parse_argument_index(const char *format, uint32_t *index)
{
	byte_t byte = 0;
	uint32_t pos = 0;

	*index = 0;

	while ((byte = *format++) != '\0')
	{
		if (byte >= '0' && byte <= '9')
		{
			*index = (*index * 10) + (byte - '0');
		}
		else
		{
			if (byte == '$')
			{
				pos++;
				break;
			}
			else
			{
				return 0;
			}
		}

		pos++;
	}

	return pos;
}

static uint32_t parse_print_specifier(const char *format, print_config *config)
{
	uint32_t pos = 0;
	uint32_t index = 0;
	byte_t byte = 0;

	memset(config, 0, sizeof(print_config));

	// argument

	// flags
	while (1)
	{
		byte = format[pos];

		if (byte == '#')
		{
			config->flags |= PRINT_ALTERNATE_FORM;
			pos++;
			continue;
		}

		if (byte == '0')
		{
			config->flags |= PRINT_ZERO_PADDED;
			pos++;
			continue;
		}

		if (byte == ' ')
		{
			config->flags |= PRINT_SPACE_PADDED;
			pos++;
			continue;
		}

		if (byte == '-')
		{
			config->flags |= PRINT_LEFT_JUSTIFY;
			pos++;
			continue;
		}

		if (byte == '+')
		{
			config->flags |= PRINT_FORCE_SIGN;
			pos++;
			continue;
		}
		if (byte == '\'')
		{
			config->flags |= PRINT_GROUP_DIGITS;
			pos++;
			continue;
		}

		break;
	}

	// width
	byte = format[pos];

	if (byte == '*')
	{
	}

	// precision
	byte = format[pos];

	if (byte == '.')
	{
		pos++;

		byte = format[pos];

		if (byte == '*')
		{
		}
	}

	// length modifiers
	byte = format[pos++];

	switch (byte)
	{
	case 'h':
	{
		if (format[pos + 1] == 'h')
		{
			config->modifier = PRINT_MOD_SHORT_SHORT;
			pos += 1;
		}
		else
		{
			config->modifier = PRINT_MOD_SHORT;
		}
	}
	break;
	case 'l':
	{
		if (format[pos + 1] == 'l')
		{
			config->modifier = PRINT_MOD_LONG_LONG;
			pos += 1;
		}
		else
		{
			config->modifier = PRINT_MOD_LONG;
		}
	}
	break;
	case 'L':
		config->modifier = PRINT_MOD_LONG_DOUBLE;
		break;
	case 'j':
		config->modifier = PRINT_MOD_INTMAX;
		break;
	case 'z':
		config->modifier = PRINT_MOD_SIZE;
		break;
	case 't':
		config->modifier = PRINT_MOD_PTRDIFF;
		break;
	}

	// conversion
	byte = format[pos++];

	switch (byte)
	{
	// integer
	case 'i':
	case 'd':
		config->type = PRINT_INT_NUMBER;
		break;
	case 'b':
		config->type = PRINT_UINT_BINARY;
		break;
	case 'o':
		config->type = PRINT_UINT_OCTAL;
		break;
	case 'X':
		config->flags |= PRINT_UPPER_CASE;
	case 'x':
		config->type = PRINT_UINT_HEX;
		break;

	// float
	case 'A':
		config->flags |= PRINT_UPPER_CASE;
	case 'a':
		config->type = PRINT_DOUBLE_HEX;
		break;
	case 'F':
		config->flags |= PRINT_UPPER_CASE;
	case 'f':
		config->type = PRINT_DOUBLE_NORMAL;
		break;
	case 'E':
		config->flags |= PRINT_UPPER_CASE;
	case 'e':
		config->type = PRINT_DOUBLE_SCIENTIFIC;
		break;
	case 'G':
		config->flags |= PRINT_UPPER_CASE;
	case 'g':
		config->type = PRINT_DOUBLE_SCIENTIFIC_SHORT;
		break;

	// misc
	case 'c':
		config->type = PRINT_CHAR;
		break;
	case 's':
		config->type = PRINT_STRING;
		break;
	case 'p':
		config->type = PRINT_POINTER;
		break;
	case 'n':
		config->type = PRINT_RESULT;
		break;

	default:
		config->type = PRINT_UNKNOWN;
		break;
	}

	return pos;
}

uint32_t vxprint(buffer_t *buffer, const char *format, va_list list)
{
	variadic_args args = {0};
	print_config config = {0};

	uint32_t result = 0;
	byte_t byte = 0;

	variadic_args_init(&args, list);

	while ((byte = *format++) != '\0')
	{
		if (byte == '%')
		{
			byte = *format++;

			if (byte == '\0')
			{
				result += writebyte(buffer, '%');
				break;
			}

			if (byte == '%')
			{
				result += writebyte(buffer, '%');
				continue;
			}

			parse_print_specifier(format, &config);

			continue;
		}

		result += writebyte(buffer, byte);
	}

	variadic_args_free(&args);

	return result;
}
