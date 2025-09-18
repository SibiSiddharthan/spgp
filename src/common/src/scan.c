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
#define SCAN_SUPPRESS_INPUT  0x1 // *
#define SCAN_GROUP_DIGITS    0x2 // '
#define SCAN_ALLOCATE_STRING 0x4 // m
#define SCAN_UPPER_CASE      0x8 // 'X|G|A|E'

// Modifiers
#define SCAN_MOD_NONE        0
#define SCAN_MOD_SHORT_SHORT 1 // hh
#define SCAN_MOD_SHORT       2 // h
#define SCAN_MOD_LONG        3 // l
#define SCAN_MOD_LONG_LONG   4 // ll

#define SCAN_MOD_MAX     5 // j
#define SCAN_MOD_SIZE    6 // z
#define SCAN_MOD_PTRDIFF 7 // t

#define SCAN_MOD_LONG_DOUBLE 8

typedef enum _scan_type
{
	SCAN_INT_NUMBER = 1,

	SCAN_UINT_NUMBER,
	SCAN_UINT_BINARY,
	SCAN_UINT_OCTAL,
	SCAN_UINT_HEX,

	SCAN_DOUBLE_NORMAL,
	SCAN_DOUBLE_HEX,
	SCAN_DOUBLE_SCIENTIFIC,
	SCAN_DOUBLE_SCIENTIFIC_SHORT,

	SCAN_CHAR,
	SCAN_STRING,
	SCAN_SET,

	SCAN_POINTER,
	SCAN_RESULT,

	SCAN_UNKNOWN

} scan_type;

typedef struct _scan_config
{
	scan_type type;
	uint16_t modifier;
	uint16_t flags;
	uint32_t width;
	uint32_t index;
	size_t result;
	void *data;
} scan_config;

static void parse_number(buffer_t *format, uint32_t *index)
{
	byte_t byte = 0;

	*index = 0;

	while ((byte = peekbyte(format, 0)) != '\0')
	{
		if (byte >= '0' && byte <= '9')
		{
			*index = (*index * 10) + (byte - '0');
			readbyte(format);
		}
		else
		{
			break;
		}
	}
}

static void parse_scan_specifier(buffer_t *format, scan_config *config, variadic_args *args)
{
	uint32_t index = 0;
	byte_t byte = 0;
	size_t pos = 0;

	memset(config, 0, sizeof(scan_config));

	// argument
	pos = format->pos;
	parse_number(format, &index);

	if (index != 0)
	{
		if (peekbyte(format, 0) == '$')
		{
			config->index = index;
			readbyte(format);
		}
		else
		{
			format->pos = pos;
		}
	}
	else
	{
		format->pos = pos;
	}

	// flags
	while ((byte = peekbyte(format, 0)) != '\0')
	{
		if (byte == '*')
		{
			config->flags |= SCAN_SUPPRESS_INPUT;
			readbyte(format);
			continue;
		}
		if (byte == '\'')
		{
			config->flags |= SCAN_GROUP_DIGITS;
			readbyte(format);
			continue;
		}
		if (byte == 'm')
		{
			config->flags |= SCAN_ALLOCATE_STRING;
			readbyte(format);
			continue;
		}

		break;
	}

	// width
	parse_number(format, &index);
	config->width = index;

	// length modifiers
	switch (byte = peekbyte(format, 0))
	{
	case 'h':
	{
		readbyte(format);

		if (peekbyte(format, 0) == 'h')
		{
			config->modifier = SCAN_MOD_SHORT_SHORT;
			readbyte(format);
		}
		else
		{
			config->modifier = SCAN_MOD_SHORT;
		}
	}
	break;
	case 'l':
	{
		readbyte(format);

		if (peekbyte(format, 0) == 'l')
		{
			config->modifier = SCAN_MOD_LONG_LONG;
			readbyte(format);
		}
		else
		{
			config->modifier = SCAN_MOD_LONG;
		}
	}
	break;
	case 'L':
		readbyte(format);
		config->modifier = SCAN_MOD_LONG_DOUBLE;
		break;
	case 'j':
		readbyte(format);
		config->modifier = SCAN_MOD_MAX;
		break;
	case 'z':
		readbyte(format);
		config->modifier = SCAN_MOD_SIZE;
		break;
	case 't':
		readbyte(format);
		config->modifier = SCAN_MOD_PTRDIFF;
		break;
	}

	// conversion
	switch (byte = readbyte(format))
	{
	// integer
	case 'i':
	case 'd':
		config->type = SCAN_INT_NUMBER;
		break;
	case 'u':
		config->type = SCAN_UINT_NUMBER;
		break;
	case 'B':
		config->flags |= SCAN_UPPER_CASE;
	case 'b':
		config->type = SCAN_UINT_BINARY;
		break;
	case 'O':
		config->flags |= SCAN_UPPER_CASE;
	case 'o':
		config->type = SCAN_UINT_OCTAL;
		break;
	case 'X':
		config->flags |= SCAN_UPPER_CASE;
	case 'x':
		config->type = SCAN_UINT_HEX;
		break;

	// float
	case 'A':
		config->flags |= SCAN_UPPER_CASE;
	case 'a':
		config->type = SCAN_DOUBLE_HEX;
		break;
	case 'F':
		config->flags |= SCAN_UPPER_CASE;
	case 'f':
		config->type = SCAN_DOUBLE_NORMAL;
		break;
	case 'E':
		config->flags |= SCAN_UPPER_CASE;
	case 'e':
		config->type = SCAN_DOUBLE_SCIENTIFIC;
		break;
	case 'G':
		config->flags |= SCAN_UPPER_CASE;
	case 'g':
		config->type = SCAN_DOUBLE_SCIENTIFIC_SHORT;
		break;

	// misc
	case 'c':
		config->type = SCAN_CHAR;
		break;
	case 's':
		config->type = SCAN_STRING;
		break;
	case 'p':
		config->type = SCAN_POINTER;
		break;
	case 'n':
		config->type = SCAN_RESULT;
		break;

	default:
		config->type = SCAN_UNKNOWN;
		break;
	}

	if (config->type != SCAN_UNKNOWN)
	{
		// get the argument from the list
		config->data = variadic_args_get(args, config->index);
	}
}

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
				if (peekbyte(buffer, 0) != byte)
				{
					break;
				}

				readbyte(&in);
				readbyte(buffer);

				continue;
			}

			continue;
		}
		else
		{

			if (peekbyte(buffer, 0) != byte)
			{
				break;
			}

			readbyte(buffer);
		}
	}

	variadic_args_free(&args);

	return result;
}
