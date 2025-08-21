/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <print.h>
#include <buffer.h>
#include <minmax.h>
#include <round.h>

#include <stdlib.h>

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

#define VARIADIC_ARGS_DEFAULT_SIZE 64

typedef struct _variadic_args
{
	va_list list;
	uint32_t count;
	void *args[VARIADIC_ARGS_DEFAULT_SIZE];

	uint32_t extra_capacity;
	void **extra_args;
} variadic_args;

static void variadic_args_init(variadic_args *args, va_list list)
{
	memset(args, 0, sizeof(variadic_args));
	args->list = list;
}

static void variadic_args_free(variadic_args *args)
{
	if (args->extra_args != NULL)
	{
		free(args->extra_args);
	}
}

static void *variadic_args_get(variadic_args *args, uint32_t index)
{
	// NOTE : index starts from 1
	if (index <= VARIADIC_ARGS_DEFAULT_SIZE)
	{
		// Read the args upto index
		for (uint32_t i = args->count; i < index; ++i)
		{
			args->args[args->count++] = va_arg(args->list, void *);
		}

		return args->args[index - 1];
	}

	// Read the args into the static storage first
	for (uint32_t i = args->count; i < VARIADIC_ARGS_DEFAULT_SIZE; ++i)
	{
		args->args[args->count++] = va_arg(args->list, void *);
	}

	if (args->extra_args == NULL || (index - VARIADIC_ARGS_DEFAULT_SIZE) > args->extra_capacity)
	{
		args->extra_capacity = MAX(4, ROUND_UP(index - VARIADIC_ARGS_DEFAULT_SIZE, 4));
		args->extra_args = realloc(args->extra_args, sizeof(void *) * args->extra_capacity);

		if (args->extra_args == NULL)
		{
			return NULL;
		}
	}

	// Read upto index args in extra space
	for (uint32_t i = args->count; i < index; ++i)
	{
		args->extra_args[args->count++ - VARIADIC_ARGS_DEFAULT_SIZE] = va_arg(args->list, void *);
	}

	return args->extra_args[index - VARIADIC_ARGS_DEFAULT_SIZE - 1];
}

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
