/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <print.h>
#include <buffer.h>

#include <stdlib.h>

#include "convert.h"
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
	uint32_t index;
	void *data;
} print_config;

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

static void parse_print_specifier(buffer_t *format, print_config *config, variadic_args *args)
{
	uint32_t index = 0;
	byte_t byte = 0;
	size_t pos = 0;

	memset(config, 0, sizeof(print_config));

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
		if (byte == '#')
		{
			config->flags |= PRINT_ALTERNATE_FORM;
			readbyte(format);
			continue;
		}

		if (byte == '0')
		{
			config->flags |= PRINT_ZERO_PADDED;
			readbyte(format);
			continue;
		}

		if (byte == ' ')
		{
			config->flags |= PRINT_SPACE_PADDED;
			readbyte(format);
			continue;
		}

		if (byte == '-')
		{
			config->flags |= PRINT_LEFT_JUSTIFY;
			readbyte(format);
			continue;
		}

		if (byte == '+')
		{
			config->flags |= PRINT_FORCE_SIGN;
			readbyte(format);
			continue;
		}
		if (byte == '\'')
		{
			config->flags |= PRINT_GROUP_DIGITS;
			readbyte(format);
			continue;
		}

		break;
	}

	// width
	if (peekbyte(format, 0) == '*')
	{
		readbyte(format);
		parse_number(format, &index);

		if (peekbyte(format, 0) == '$')
		{
			readbyte(format);
			config->width = (uint32_t)(uintptr_t)variadic_args_get(args, index);
		}
		else
		{
			config->width = (uint32_t)(uintptr_t)variadic_args_get(args, 0);
		}
	}
	else
	{
		parse_number(format, &index);
		config->width = index;
	}

	// precision
	if (peekbyte(format, 0) == '.')
	{
		readbyte(format);

		if (peekbyte(format, 0) == '*')
		{
			readbyte(format);
			parse_number(format, &index);

			if (peekbyte(format, 0) == '$')
			{
				readbyte(format);
				config->width = (uint32_t)(uintptr_t)variadic_args_get(args, index);
			}
			else
			{
				config->width = (uint32_t)(uintptr_t)variadic_args_get(args, 0);
			}
		}
		else
		{
			parse_number(format, &index);
			config->precision = index;
		}
	}

	// length modifiers
	switch (byte = peekbyte(format, 0))
	{
	case 'h':
	{
		readbyte(format);

		if (peekbyte(format, 0) == 'h')
		{
			config->modifier = PRINT_MOD_SHORT_SHORT;
			readbyte(format);
		}
		else
		{
			config->modifier = PRINT_MOD_SHORT;
		}
	}
	break;
	case 'l':
	{
		readbyte(format);

		if (peekbyte(format, 0) == 'l')
		{
			config->modifier = PRINT_MOD_LONG_LONG;
			readbyte(format);
		}
		else
		{
			config->modifier = PRINT_MOD_LONG;
		}
	}
	break;
	case 'L':
		readbyte(format);
		config->modifier = PRINT_MOD_LONG_DOUBLE;
		break;
	case 'j':
		readbyte(format);
		config->modifier = PRINT_MOD_INTMAX;
		break;
	case 'z':
		readbyte(format);
		config->modifier = PRINT_MOD_SIZE;
		break;
	case 't':
		readbyte(format);
		config->modifier = PRINT_MOD_PTRDIFF;
		break;
	}

	// conversion
	switch (byte = readbyte(format))
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

	if (config->type != PRINT_UNKNOWN)
	{
		// get the argument from the list
		config->data = variadic_args_get(args, config->index);
	}
}

static void print_arg(buffer_t *buffer, print_config *config)
{
	char temp[128] = {0};

	if (config->type == PRINT_UINT_BINARY || config->type == PRINT_UINT_OCTAL || config->type == PRINT_UINT_HEX ||
		config->type == PRINT_UINT_NUMBER || config->type == PRINT_INT_NUMBER)
	{
		if (config->type == PRINT_UINT_BINARY)
		{
			switch (config->modifier)
			{
			case PRINT_MOD_NONE:
				u32_to_bin(temp, (uint32_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT:
				u16_to_bin(temp, (uint16_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT_SHORT:
				u8_to_bin(temp, (uint8_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG:
				u64_to_bin(temp, (uint64_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG_LONG:
			case PRINT_MOD_INTMAX:
				umax_to_bin(temp, (uintmax_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SIZE:
				usize_to_bin(temp, (uintmax_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_PTRDIFF:
				uptr_to_bin(temp, (uint32_t)(uintptr_t)config->data);
				break;
			}
		}
	}
}

uint32_t vxprint(buffer_t *buffer, const char *format, va_list list)
{
	variadic_args args = {0};
	print_config config = {0};
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
				result += writebyte(buffer, '%');
				break;
			}

			if (byte == '%')
			{
				result += writebyte(buffer, '%');
				readbyte(&in);

				continue;
			}

			pos = in.pos;
			parse_print_specifier(&in, &config, &args);

			if (config.type == PRINT_UNKNOWN)
			{
				in.pos = pos;
				result += writebyte(buffer, byte);

				continue;
			}

			print_arg(buffer, &config);
			continue;
		}

		result += writebyte(buffer, byte);
	}

	variadic_args_free(&args);

	return result;
}
