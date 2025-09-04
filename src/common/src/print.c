/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <print.h>
#include <buffer.h>

#include "convert.h"
#include "varargs.h"

// Flags
#define PRINT_ALTERNATE_FORM 0x01 // '#'
#define PRINT_ZERO_PADDED    0x02 // '0'
#define PRINT_EMPTY_SPACE    0x04 // ' '
#define PRINT_LEFT_JUSTIFY   0x08 // '-'
#define PRINT_FORCE_SIGN     0x10 // '+'
#define PRINT_UPPER_CASE     0x20 // 'X|G|A|E'
#define PRINT_GROUP_DIGITS   0x40 // '''

// Modifiers
#define PRINT_MOD_NONE        0
#define PRINT_MOD_SHORT_SHORT 1 // hh
#define PRINT_MOD_SHORT       2 // h
#define PRINT_MOD_LONG        3 // l
#define PRINT_MOD_LONG_LONG   4 // ll

#define PRINT_MOD_MAX     5 // j
#define PRINT_MOD_SIZE    6 // z
#define PRINT_MOD_PTRDIFF 7 // t

#define PRINT_MOD_LONG_DOUBLE 8

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

typedef struct _print_config
{
	print_type type;
	uint16_t modifier;
	uint16_t flags;
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
			config->flags |= PRINT_EMPTY_SPACE;
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
		config->modifier = PRINT_MOD_MAX;
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
	case 'B':
		config->flags |= PRINT_UPPER_CASE;
	case 'b':
		config->type = PRINT_UINT_BINARY;
		break;
	case 'O':
		config->flags |= PRINT_UPPER_CASE;
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

	// If both '-' and '0' are given '0' is ignored.
	if (config->flags & PRINT_LEFT_JUSTIFY)
	{
		config->flags &= ~PRINT_ZERO_PADDED;
	}

	// Ignore '0' if precision is greater than 0
	if (config->precision > 0)
	{
		config->flags &= ~PRINT_ZERO_PADDED;
	}

	//  If both '+' and ' ' are given ' ' is ignored.
	if (config->flags & PRINT_FORCE_SIGN)
	{
		config->flags &= ~PRINT_EMPTY_SPACE;
	}
}

static uint32_t print_arg(buffer_t *buffer, print_config *config)
{
	byte_t temp[128] = {0};
	uint32_t result = 0;
	uint32_t pos = 0;
	uint32_t size = 0;
	uint32_t extra = 0;

	if (config->type == PRINT_UINT_BINARY || config->type == PRINT_UINT_OCTAL || config->type == PRINT_UINT_HEX ||
		config->type == PRINT_UINT_NUMBER || config->type == PRINT_INT_NUMBER)
	{
		if (config->type == PRINT_UINT_BINARY)
		{
			switch (config->modifier)
			{
			case PRINT_MOD_NONE:
				size = u32_to_bin(temp, (uint32_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT:
				size = u16_to_bin(temp, (uint16_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT_SHORT:
				size = u8_to_bin(temp, (uint8_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG:
				size = u64_to_bin(temp, (uint64_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG_LONG:
			case PRINT_MOD_MAX:
				size = umax_to_bin(temp, (uintmax_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SIZE:
				size = usize_to_bin(temp, (size_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_PTRDIFF:
				size = uptr_to_bin(temp, (uintptr_t)config->data);
				break;
			}
		}

		if (config->type == PRINT_UINT_OCTAL)
		{
			switch (config->modifier)
			{
			case PRINT_MOD_NONE:
				size = u32_to_oct(temp, (uint32_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT:
				size = u16_to_oct(temp, (uint16_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT_SHORT:
				size = u8_to_oct(temp, (uint8_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG:
				size = u64_to_oct(temp, (uint64_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG_LONG:
			case PRINT_MOD_MAX:
				size = umax_to_oct(temp, (uintmax_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SIZE:
				size = usize_to_oct(temp, (size_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_PTRDIFF:
				size = uptr_to_oct(temp, (uintptr_t)config->data);
				break;
			}
		}

		if (config->type == PRINT_UINT_HEX)
		{
			switch (config->modifier)
			{
			case PRINT_MOD_NONE:
				size = u32_to_hex(temp, (config->flags & PRINT_UPPER_CASE), (uint32_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT:
				size = u16_to_hex(temp, (config->flags & PRINT_UPPER_CASE), (uint16_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT_SHORT:
				size = u8_to_hex(temp, (config->flags & PRINT_UPPER_CASE), (uint8_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG:
				size = u64_to_hex(temp, (config->flags & PRINT_UPPER_CASE), (uint64_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG_LONG:
			case PRINT_MOD_MAX:
				size = umax_to_hex(temp, (config->flags & PRINT_UPPER_CASE), (uintmax_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SIZE:
				size = usize_to_hex(temp, (config->flags & PRINT_UPPER_CASE), (size_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_PTRDIFF:
				size = uptr_to_hex(temp, (config->flags & PRINT_UPPER_CASE), (uintptr_t)config->data);
				break;
			}
		}

		if (config->type == PRINT_UINT_NUMBER)
		{
			switch (config->modifier)
			{
			case PRINT_MOD_NONE:
				size = u32_to_dec(temp, (uint32_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT:
				size = u16_to_dec(temp, (uint16_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SHORT_SHORT:
				size = u8_to_dec(temp, (uint8_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG:
				size = u64_to_dec(temp, (uint64_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_LONG_LONG:
			case PRINT_MOD_MAX:
				size = umax_to_dec(temp, (uintmax_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_SIZE:
				size = usize_to_dec(temp, (size_t)(uintptr_t)config->data);
				break;
			case PRINT_MOD_PTRDIFF:
				size = uptr_to_dec(temp, (uintptr_t)config->data);
				break;
			}
		}

		if (config->type == PRINT_INT_NUMBER)
		{
			switch (config->modifier)
			{
			case PRINT_MOD_NONE:
				size = i32_to_dec(temp, (int32_t)(intptr_t)config->data);
				break;
			case PRINT_MOD_SHORT:
				size = i16_to_dec(temp, (int16_t)(intptr_t)config->data);
				break;
			case PRINT_MOD_SHORT_SHORT:
				size = i8_to_dec(temp, (int8_t)(intptr_t)config->data);
				break;
			case PRINT_MOD_LONG:
				size = i64_to_dec(temp, (int64_t)(intptr_t)config->data);
				break;
			case PRINT_MOD_LONG_LONG:
			case PRINT_MOD_MAX:
				size = imax_to_dec(temp, (intmax_t)(intptr_t)config->data);
				break;
			case PRINT_MOD_SIZE:
				size = isize_to_dec(temp, (ssize_t)(intptr_t)config->data);
				break;
			case PRINT_MOD_PTRDIFF:
				size = iptr_to_dec(temp, (intptr_t)config->data);
				break;
			}
		}

		if (config->flags & PRINT_ALTERNATE_FORM)
		{
			if (config->type == PRINT_UINT_HEX || config->type == PRINT_UINT_OCTAL || config->type == PRINT_UINT_BINARY)
			{
				extra += 2;
			}
		}

		if (config->flags & PRINT_FORCE_SIGN)
		{
			if (config->type == PRINT_UINT_NUMBER || config->type == PRINT_INT_NUMBER)
			{
				extra += 1;
			}
		}

		if (size + extra < MAX(config->precision, config->width))
		{
			if (config->precision < config->width)
			{
				if (config->flags & PRINT_ZERO_PADDED)
				{
				}
				else
				{
				}
			}
			else
			{
			}
		}

		if (config->flags & PRINT_FORCE_SIGN)
		{
			if (config->type == PRINT_UINT_NUMBER)
			{
				writebyte(buffer, '+');
			}

			if (config->type == PRINT_INT_NUMBER)
			{
				if ((intmax_t)(intptr_t)config->data < 0)
				{
					writebyte(buffer, '-');
				}
				else
				{
					writebyte(buffer, '+');
				}
			}
		}

		if (config->flags & PRINT_ALTERNATE_FORM)
		{
			byte_t byte = 0;

			if (config->type == PRINT_UINT_HEX)
			{
				byte = 'x';
			}

			if (config->type == PRINT_UINT_OCTAL)
			{
				byte = 'o';
			}

			if (config->type == PRINT_UINT_BINARY)
			{
				byte = 'b';
			}

			if (config->flags & PRINT_UPPER_CASE)
			{
				byte &= ~0x20;
			}

			writebyte(buffer, '0');
			writebyte(buffer, byte);
		}
	}

	if (config->type == PRINT_CHAR)
	{
		byte_t pre_temp[8] = {0};
		uint32_t codepoint = 0;

		switch (config->modifier)
		{
		case PRINT_MOD_NONE:
			pre_temp[0] = (byte_t)(uintptr_t)config->data;
			size = 1;
			break;
		case PRINT_MOD_LONG:
			if (utf16_decode(config->data, 8, &codepoint) != 0)
				size = utf8_encode(pre_temp, codepoint);
			break;
		case PRINT_MOD_LONG_LONG:
			codepoint = (uint32_t)(uintptr_t)config->data;
			size = utf8_encode(pre_temp, codepoint);
			break;
		default:
			pre_temp[0] = (byte_t)(uintptr_t)config->data;
			size = 1;
			break;
		}

		if (config->modifier == PRINT_MOD_NONE)
		{
			if (config->width > 1)
			{
				if (config->flags & PRINT_LEFT_JUSTIFY)
				{
					for (uint32_t i = 0; i < size; ++i)
					{
						temp[pos++] = pre_temp[i];
					}

					for (uint32_t i = 1; i < config->width; ++i)
					{
						temp[pos++] = ' ';
					}
				}
				else
				{
					for (uint32_t i = 0; i < config->width - 1; ++i)
					{
						temp[pos++] = ' ';
					}

					for (uint32_t i = 0; i < size; ++i)
					{
						temp[pos++] = pre_temp[i];
					}
				}

				writen(buffer, temp, pos);
				result = pos;
			}
			else
			{
				writen(buffer, pre_temp, size);
				result = size;
			}
		}

		return result;
	}

	return 0;
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
				writebyte(buffer, '%');
				result += 1;
				break;
			}

			if (byte == '%')
			{
				readbyte(&in);

				writebyte(buffer, '%');
				result += 1;

				continue;
			}

			pos = in.pos;
			parse_print_specifier(&in, &config, &args);

			if (config.type == PRINT_UNKNOWN)
			{
				in.pos = pos;
				writebyte(buffer, byte);
				result += 1;

				continue;
			}

			result += print_arg(buffer, &config);
			continue;
		}

		writebyte(buffer, byte);
		result += 1;
	}

	variadic_args_free(&args);

	return result;
}
