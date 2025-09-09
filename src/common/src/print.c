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
#define PRINT_PRECISION      0x80 // precision specified

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
				config->precision = (uint32_t)(uintptr_t)variadic_args_get(args, index);
			}
			else
			{
				config->precision = (uint32_t)(uintptr_t)variadic_args_get(args, 0);
			}
		}
		else
		{
			parse_number(format, &index);
			config->precision = index;
		}

		config->flags |= PRINT_PRECISION;
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
	case 'u':
		config->type = PRINT_UINT_NUMBER;
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

	// Ignore '0' if precision is given
	if (config->flags & PRINT_PRECISION)
	{
		config->flags &= ~PRINT_ZERO_PADDED;
	}

	//  If both '+' and ' ' are given ' ' is ignored.
	if (config->flags & PRINT_FORCE_SIGN)
	{
		config->flags &= ~PRINT_EMPTY_SPACE;
	}
}

static byte_t alternate_form_char(print_config *config)
{
	switch (config->type)
	{
	case PRINT_UINT_BINARY:
		return config->flags & PRINT_UPPER_CASE ? 'B' : 'b';
	case PRINT_UINT_OCTAL:
		return config->flags & PRINT_UPPER_CASE ? 'O' : 'o';
	case PRINT_UINT_HEX:
		return config->flags & PRINT_UPPER_CASE ? 'X' : 'x';
	default:
		return 0;
	}
}

static uint32_t print_uint_formatted(print_config *config, buffer_t *buffer, byte_t *temp, uint32_t size)
{
	uint32_t result = 0;
	uint32_t pos = 0;

	if (config->flags & PRINT_LEFT_JUSTIFY)
	{
		if (config->flags & PRINT_ALTERNATE_FORM)
		{
			writebyte(buffer, '0');
			writebyte(buffer, alternate_form_char(config));

			pos += 2;
		}

		while (size < config->precision)
		{
			writebyte(buffer, '0');
			size += 1;
		}

		size += pos;

		while (size < config->width)
		{
			writebyte(buffer, ' ');
			size += 1;
		}

		result = size;

		return result;
	}

	if (config->width > MAX(config->precision, size))
	{
		if (config->flags & PRINT_ZERO_PADDED)
		{
			if (config->flags & PRINT_ALTERNATE_FORM)
			{
				writebyte(buffer, '0');
				writebyte(buffer, alternate_form_char(config));

				pos += 2;
			}

			while (pos + size < config->width)
			{
				writebyte(buffer, '0');
				pos += 1;
			}

			writen(buffer, temp, size);
			result = pos + size;
		}
		else
		{
			uint32_t count = MAX(config->precision, size) + (config->flags & PRINT_ALTERNATE_FORM ? 2 : 0);

			while (pos + count < config->width)
			{
				writebyte(buffer, ' ');
				pos += 1;
			}

			if (config->flags & PRINT_ALTERNATE_FORM)
			{
				writebyte(buffer, '0');
				writebyte(buffer, alternate_form_char(config));

				pos += 2;
			}

			writen(buffer, temp, size);
			result = size + pos;
		}
	}
	else
	{
		uint32_t extra = 0;

		if (config->flags & PRINT_ALTERNATE_FORM)
		{
			writebyte(buffer, '0');
			writebyte(buffer, alternate_form_char(config));

			extra += 2;
		}

		while (pos + size < config->precision)
		{
			writebyte(buffer, '0');
			pos += 1;
		}

		writen(buffer, temp, size);
		result = pos + size + extra;
	}

	return result;
}

static uint32_t print_arg(buffer_t *buffer, print_config *config)
{
	byte_t temp[128] = {0};
	uint32_t result = 0;
	uint32_t pos = 0;
	uint32_t size = 0;

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
			size = imax_to_dec(temp, (intmax_t)(intptr_t)config->data);
			break;
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

		return result;
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
			size = umax_to_dec(temp, (uintmax_t)(uintptr_t)config->data);
			break;
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

		return result;
	}

	if (config->type == PRINT_UINT_BINARY)
	{
		switch (config->modifier)
		{
		case PRINT_MOD_NONE:
			size = u32_to_bin(temp + pos, (uint32_t)(uintptr_t)config->data);
			break;
		case PRINT_MOD_SHORT:
			size = u16_to_bin(temp + pos, (uint16_t)(uintptr_t)config->data);
			break;
		case PRINT_MOD_SHORT_SHORT:
			size = u8_to_bin(temp + pos, (uint8_t)(uintptr_t)config->data);
			break;
		case PRINT_MOD_LONG:
			size = u64_to_bin(temp + pos, (uint64_t)(uintptr_t)config->data);
			break;
		case PRINT_MOD_LONG_LONG:
			size = umax_to_bin(temp + pos, (uintmax_t)(uintptr_t)config->data);
			break;
		case PRINT_MOD_MAX:
			size = umax_to_bin(temp + pos, (uintmax_t)(uintptr_t)config->data);
			break;
		case PRINT_MOD_SIZE:
			size = usize_to_bin(temp + pos, (size_t)(uintptr_t)config->data);
			break;
		case PRINT_MOD_PTRDIFF:
			size = uptr_to_bin(temp + pos, (uintptr_t)config->data);
			break;
		}

		return print_uint_formatted(config, buffer, temp, size);
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

		return print_uint_formatted(config, buffer, temp, size);
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

		return print_uint_formatted(config, buffer, temp, size);
	}

	if (config->type == PRINT_UINT_OCTAL || config->type == PRINT_UINT_HEX)
	{
		if (config->flags & PRINT_ALTERNATE_FORM)
		{
			if (config->type == PRINT_UINT_HEX || config->type == PRINT_UINT_OCTAL || config->type == PRINT_UINT_BINARY)
			{
			}
		}

		if (config->flags & PRINT_FORCE_SIGN)
		{
			if (config->type == PRINT_UINT_NUMBER || config->type == PRINT_INT_NUMBER)
			{
			}
		}

		if (size < MAX(config->precision, config->width))
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
			if (utf16_decode(&config->data, 8, &codepoint) != 0)
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

		return result;
	}

	if (config->type == PRINT_STRING)
	{
		size_t count = 0;

		if ((config->flags & PRINT_PRECISION) == 0)
		{
			config->precision = UINT32_MAX;
		}

		switch (config->modifier)
		{
		case PRINT_MOD_NONE:
		{
			byte_t *ch = config->data;

			while (*ch++ != 0 && count < config->precision)
			{
				++count;
			}
		}
		break;
		case PRINT_MOD_LONG:
		{
			uint16_t *ch = config->data;

			while (*ch++ != 0 && count < config->precision)
			{
				++count;
			}
		}
		break;
		case PRINT_MOD_LONG_LONG:
		{
			uint32_t *ch = config->data;

			while (*ch++ != 0 && count < config->precision)
			{
				++count;
			}
		}
		break;
		default:
		{
			byte_t *ch = config->data;

			while (*ch++ != 0 && count < config->precision)
			{
				++count;
			}
		}
		break;
		}

		if (config->width > count)
		{
			if ((config->flags & PRINT_LEFT_JUSTIFY) == 0)
			{
				for (uint32_t i = 0; i < config->width - count; ++i)
				{
					writebyte(buffer, ' ');
					result += 1;
				}
			}
		}

		switch (config->modifier)
		{
		case PRINT_MOD_NONE:
		{
			writen(buffer, config->data, count * sizeof(byte_t));
			result += count * sizeof(byte_t);
		}
		break;
		case PRINT_MOD_LONG:
		{
			uint32_t codepoint = 0;
			pos = 0;

			for (uint32_t i = 0; i < count; ++i)
			{
				size = utf16_decode(PTR_OFFSET(config->data, pos), 4, &codepoint);
				pos += size;

				if (size == 4)
				{
					++i;
				}

				if (codepoint == 0)
				{
					break;
				}

				size = utf8_encode(temp, codepoint);
				writen(buffer, temp, size);
				result += size;
			}
		}
		break;
		case PRINT_MOD_LONG_LONG:
		{
			uint32_t *ch = config->data;

			for (uint32_t i = 0; i < count; ++i)
			{
				size = utf8_encode(temp, *ch++);
				writen(buffer, temp, size);
				result += size;
			}
		}
		break;
		default:
		{
			writen(buffer, config->data, count * sizeof(byte_t));
			result += count * sizeof(byte_t);
		}
		break;
		}

		if (config->width > count)
		{
			if (config->flags & PRINT_LEFT_JUSTIFY)
			{
				for (uint32_t i = 0; i < config->width - count; ++i)
				{
					writebyte(buffer, ' ');
					result += 1;
				}
			}
		}

		return result;
	}

	if (config->type == PRINT_POINTER)
	{
		size = pointer_encode(temp, config->data);

		if (config->width > size)
		{
			if (config->flags & PRINT_LEFT_JUSTIFY)
			{
				writen(buffer, temp, size);

				for (uint32_t i = size; i < config->width; ++i)
				{
					writebyte(buffer, ' ');
					size += 1;
				}
			}
			else
			{
				for (uint32_t i = 0; i < config->width - size; ++i)
				{
					writebyte(buffer, ' ');
					pos += 1;
				}

				writen(buffer, temp, size);
				size += pos;
			}

			result = size;
		}
		else
		{
			writen(buffer, temp, size);
			result = size;
		}

		return result;
	}

	if (config->type == PRINT_RESULT)
	{
		switch (config->modifier)
		{
		case PRINT_MOD_NONE:
			*(int32_t *)config->data = (int32_t)buffer->pos;
			break;
		case PRINT_MOD_SHORT:
			*(int16_t *)config->data = (int16_t)buffer->pos;
			break;
		case PRINT_MOD_SHORT_SHORT:
			*(int8_t *)config->data = (int8_t)buffer->pos;
			break;
		case PRINT_MOD_LONG:
			*(int64_t *)config->data = (int64_t)buffer->pos;
			break;
		case PRINT_MOD_LONG_LONG:
			*(int64_t *)config->data = (int64_t)buffer->pos;
			break;
		case PRINT_MOD_MAX:
			*(intmax_t *)config->data = (intmax_t)buffer->pos;
			break;
		case PRINT_MOD_SIZE:
			*(size_t *)config->data = (size_t)buffer->pos;
			break;
		case PRINT_MOD_PTRDIFF:
			*(ptrdiff_t *)config->data = (ptrdiff_t)buffer->pos;
			break;
		}

		return 0;
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
