/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <minmax.h>
#include <round.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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
