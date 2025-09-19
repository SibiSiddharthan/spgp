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
#define SCAN_SUPPRESS_INPUT  0x01 // *
#define SCAN_ALLOCATE_STRING 0x02 // m
#define SCAN_UPPER_CASE      0x20 // 'X|G|A|E'
#define SCAN_GROUP_DIGITS    0x40 // '

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

#define IS_SPACE(x) ((x) == ' ' || ((x) >= '\t' && (x) <= '\r'))

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

static uint32_t consume_whitespaces(buffer_t *buffer)
{
	uint32_t count = 0;
	byte_t byte = 0;

	while ((byte = peekbyte(buffer, 0)) != '\0')
	{
		if (IS_SPACE(byte))
		{
			readbyte(buffer);
			count += 1;

			continue;
		}

		break;
	}

	return count;
}

static uint32_t scan_arg(buffer_t *buffer, scan_config *config)
{
	uint32_t result = 0;
	size_t old_size = 0;

	if (config->type == SCAN_INT_NUMBER)
	{
		result += consume_whitespaces(buffer);

		if (config->width > 0)
		{
			old_size = buffer->size;
			buffer->size = buffer->pos + config->width;
		}

		switch (config->modifier)
		{
		case SCAN_MOD_NONE:
			result += i32_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_SHORT:
			result += i16_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_SHORT_SHORT:
			result += i8_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_LONG:
			result += i64_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_LONG_LONG:
			result += imax_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_MAX:
			result += imax_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_SIZE:
			result += isize_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_PTRDIFF:
			result += iptr_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		}

		if (config->width > 0)
		{
			buffer->size = old_size;
		}

		return result;
	}

	if (config->type == SCAN_UINT_NUMBER)
	{
		result += consume_whitespaces(buffer);

		if (config->width > 0)
		{
			old_size = buffer->size;
			buffer->size = buffer->pos + config->width;
		}

		switch (config->modifier)
		{
		case SCAN_MOD_NONE:
			result += u32_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_SHORT:
			result += u16_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_SHORT_SHORT:
			result += u8_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_LONG:
			result += u64_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_LONG_LONG:
			result += umax_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_MAX:
			result += umax_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_SIZE:
			result += usize_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		case SCAN_MOD_PTRDIFF:
			result += uptr_from_dec(buffer, config->data, config->flags & SCAN_GROUP_DIGITS);
			break;
		}

		if (config->width > 0)
		{
			buffer->size = old_size;
		}

		return result;
	}

	if (config->type == SCAN_UINT_BINARY)
	{
		result += consume_whitespaces(buffer);

		if (config->width > 0)
		{
			old_size = buffer->size;
			buffer->size = buffer->pos + config->width;
		}

		if (peekbyte(buffer, 0) == '0' && (peekbyte(buffer, 1) == 'b' || peekbyte(buffer, 1) == 'B'))
		{
			readbyte(buffer);
			readbyte(buffer);
		}

		switch (config->modifier)
		{
		case SCAN_MOD_NONE:
			result += u32_from_bin(buffer, config->data);
			break;
		case SCAN_MOD_SHORT:
			result += u16_from_bin(buffer, config->data);
			break;
		case SCAN_MOD_SHORT_SHORT:
			result += u8_from_bin(buffer, config->data);
			break;
		case SCAN_MOD_LONG:
			result += u64_from_bin(buffer, config->data);
			break;
		case SCAN_MOD_LONG_LONG:
			result += umax_from_bin(buffer, config->data);
			break;
		case SCAN_MOD_MAX:
			result += umax_from_bin(buffer, config->data);
			break;
		case SCAN_MOD_SIZE:
			result += usize_from_bin(buffer, config->data);
			break;
		case SCAN_MOD_PTRDIFF:
			result += uptr_from_bin(buffer, config->data);
			break;
		}

		if (config->width > 0)
		{
			buffer->size = old_size;
		}

		return result;
	}

	if (config->type == SCAN_UINT_OCTAL)
	{
		result += consume_whitespaces(buffer);

		if (config->width > 0)
		{
			old_size = buffer->size;
			buffer->size = buffer->pos + config->width;
		}

		if (peekbyte(buffer, 0) == '0')
		{
			readbyte(buffer);

			if (peekbyte(buffer, 1) == 'o' || peekbyte(buffer, 1) == 'O')
			{
				readbyte(buffer);
			}
		}

		switch (config->modifier)
		{
		case SCAN_MOD_NONE:
			result += u32_from_oct(buffer, config->data);
			break;
		case SCAN_MOD_SHORT:
			result += u16_from_oct(buffer, config->data);
			break;
		case SCAN_MOD_SHORT_SHORT:
			result += u8_from_oct(buffer, config->data);
			break;
		case SCAN_MOD_LONG:
			result += u64_from_oct(buffer, config->data);
			break;
		case SCAN_MOD_LONG_LONG:
			result += umax_from_oct(buffer, config->data);
			break;
		case SCAN_MOD_MAX:
			result += umax_from_oct(buffer, config->data);
			break;
		case SCAN_MOD_SIZE:
			result += usize_from_oct(buffer, config->data);
			break;
		case SCAN_MOD_PTRDIFF:
			result += uptr_from_oct(buffer, config->data);
			break;
		}

		if (config->width > 0)
		{
			buffer->size = old_size;
		}

		return result;
	}

	if (config->type == SCAN_RESULT)
	{
		switch (config->modifier)
		{
		case SCAN_MOD_NONE:
			*(int32_t *)config->data = (int32_t)config->result;
			break;
		case SCAN_MOD_SHORT:
			*(int16_t *)config->data = (int16_t)config->result;
			break;
		case SCAN_MOD_SHORT_SHORT:
			*(int8_t *)config->data = (int8_t)config->result;
			break;
		case SCAN_MOD_LONG:
			*(int64_t *)config->data = (int64_t)config->result;
			break;
		case SCAN_MOD_LONG_LONG:
			*(int64_t *)config->data = (int64_t)config->result;
			break;
		case SCAN_MOD_MAX:
			*(intmax_t *)config->data = (intmax_t)config->result;
			break;
		case SCAN_MOD_SIZE:
			*(size_t *)config->data = (size_t)config->result;
			break;
		case SCAN_MOD_PTRDIFF:
			*(ptrdiff_t *)config->data = (ptrdiff_t)config->result;
			break;
		}

		return 0;
	}

	return 0;
}

uint32_t vxscan(buffer_t *buffer, const char *format, va_list list)
{
	variadic_args args = {0};
	scan_config config = {0};
	buffer_t in = {.data = (void *)format, .pos = 0, .size = strnlen(format, 65536)};

	uint32_t processed = 0;
	uint32_t count = 0;
	byte_t byte = 0;

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

				processed += 1;

				continue;
			}

			parse_scan_specifier(&in, &config, &args);

			if (config.type == SCAN_UNKNOWN)
			{
				break;
			}

			config.result = processed;
			processed += scan_arg(buffer, &config);

			if (config.type != SCAN_RESULT)
			{
				count += 1;
			}

			continue;
		}
		else
		{
			if (IS_SPACE(byte))
			{
				continue;
			}

			if (peekbyte(buffer, 0) != byte)
			{
				break;
			}

			readbyte(buffer);
			processed += 1;
		}
	}

	variadic_args_free(&args);

	return count;
}
