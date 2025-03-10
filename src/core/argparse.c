/*
   Copyright (c) 2020-2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <argparse.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static arg_option_t *argparse_find_subcommand(argparse_t *actx, char *arg)
{
	for (uint32_t i = 0; i < actx->option_count; ++i)
	{
		if (actx->options[i].long_option != NULL && actx->options[i].argument_type == ARGPARSE_OPTION_SUBCOMMAND)
		{
			if (strcmp(actx->options[i].long_option, arg) == 0)
			{
				return &actx->options[i];
			}
		}
	}

	return NULL;
}

static arg_option_t *argparse_find_short_option(argparse_t *actx, char arg)
{
	for (uint32_t i = 0; i < actx->option_count; ++i)
	{
		if (actx->options[i].short_option == arg)
		{
			return &actx->options[i];
		}
	}

	return NULL;
}

static arg_option_t *argparse_find_long_option(argparse_t *actx, char *arg, uint32_t size)
{
	for (uint32_t i = 0; i < actx->option_count; ++i)
	{
		if (actx->options[i].long_option != NULL)
		{
			if (strncmp(actx->options[i].long_option, arg, size) == 0)
			{
				return &actx->options[i];
			}
		}
	}

	return NULL;
}

static argparse_t *argparse_result_push(argparse_t *actx, uint16_t value, void *data)
{
	if (actx->result_capacity == 0)
	{
		actx->result_capacity = 4;
		actx->results = malloc(sizeof(arg_result_t) * actx->result_capacity);

		if (actx->results == NULL)
		{
			return NULL;
		}

		memset(actx->results, 0, sizeof(arg_result_t) * actx->result_capacity);
	}

	if (actx->result_capacity == actx->result_count)
	{
		actx->results = realloc(actx->results, sizeof(arg_result_t) * actx->result_capacity * 2);

		if (actx->results == NULL)
		{
			return NULL;
		}

		memset(PTR_OFFSET(actx->results, sizeof(arg_result_t) * actx->result_capacity), 0, sizeof(arg_result_t) * actx->result_capacity);
		actx->result_capacity *= 2;
	}

	actx->results[actx->result_count].value = value;
	actx->results[actx->result_count].data = data;

	actx->result_count += 1;

	return actx;
}

static argparse_t *argparse_process_long_option(argparse_t *actx, arg_option_t *option, void *equal)
{
	void *result = NULL;
	void *value = NULL;
	char *oarg = NULL;

	if (option->argument_type == ARGPARSE_OPTION_ARGUMENT_NONE)
	{
		actx->arg_index += 1;
		value = NULL;
	}

	if (option->argument_type == ARGPARSE_OPTION_ARGUMENT_REQUIRED)
	{
		actx->arg_index += 1;

		if (equal != NULL)
		{
			value = PTR_OFFSET(equal, 1);
		}
		else
		{
			value = actx->args[actx->arg_index];
			actx->arg_index += 1;
		}
	}

	if (option->argument_type == ARGPARSE_OPTION_ARGUMENT_OPTIONAL)
	{
		actx->arg_index += 1;

		if (equal != NULL)
		{
			value = PTR_OFFSET(equal, 1);
		}
		else
		{
			oarg = actx->args[actx->arg_index];

			if (oarg[0] != '-')
			{
				value = actx->args[actx->arg_index];
				actx->arg_index += 1;
			}
			else
			{
				value = NULL;
			}
		}
	}

	result = argparse_result_push(actx, option->return_value, value);

	if (result == NULL)
	{
		argparse_delete(actx);
		return NULL;
	}

	return actx;
}

argparse_t *argparse_new(uint32_t arg_count, void **args, uint32_t option_count, arg_option_t *options, uint32_t flags)
{
	argparse_t *actx = NULL;
	void *result = NULL;

	actx = malloc(sizeof(argparse_t));

	if (actx == NULL)
	{
		return NULL;
	}

	memset(actx, 0, sizeof(argparse_t));

	actx->arg_count = arg_count;
	actx->arg_index = 0;
	actx->args = args;

	actx->option_count = option_count;
	actx->options = options;

	actx->flags = flags;

	// Skip argv[0]
	if (actx->flags & ARGPARSE_FLAG_SKIP_FIRST_ARGUMENT)
	{
		actx->arg_index += 1;
	}

	while (actx->arg_index < actx->arg_count)
	{
		uint32_t pos = 0;
		char *argument = actx->args[actx->arg_index];

		if (argument[pos] == '-')
		{
			if (argument[pos + 1] == '-')
			{
				if (argument[pos + 2] == '\0')
				{
					// End of options.
					// Remaining arguments are considered as non options
					actx->arg_index += 1;
					goto consume_remaining_args;
				}
				else
				{
					// Process the long options

					arg_option_t *option = NULL;
					void *equal = NULL;
					char *oarg = argument + 2; // consume '--'
					uint32_t size = 0;

					// Find '='
					equal = strchr(oarg, '=');

					if (equal != NULL)
					{
						size = (uint32_t)((uintptr_t)equal - (uintptr_t)oarg);
					}
					else
					{
						size = strlen(oarg);
					}

					option = argparse_find_long_option(actx, oarg, size);

					// Unknown options
					if (option == NULL)
					{
						result = argparse_result_push(actx, ARGPARSE_RETURN_UNKNOWN_LONG_OPTION, actx->args[actx->arg_index]);
						actx->arg_index += 1;

						if (result == NULL)
						{
							argparse_delete(actx);
							return NULL;
						}

						continue;
					}

					result = argparse_process_long_option(actx, option, equal);

					if (result == NULL)
					{
						argparse_delete(actx);
						return NULL;
					}

					continue;
				}
			}
			else if (argument[pos + 1] != '-' && argument[pos + 1] != '\0')
			{
				// Process the short (or long) options

				arg_option_t *option = NULL;
				void *value = NULL;

				pos += 1;

				// Prefer long options to short options
				if (actx->flags & ARGPARSE_FLAG_ALLOW_LONG_ONLY)
				{
					char *oarg = argument + 1;
					void *equal = NULL;
					uint32_t size = 0;

					// Find '='
					equal = strchr(oarg, '=');

					if (equal != NULL)
					{
						size = (uint32_t)((uintptr_t)equal - (uintptr_t)oarg);
					}
					else
					{
						size = strlen(oarg);
					}

					option = argparse_find_long_option(actx, oarg, size);

					if (option != NULL)
					{
						result = argparse_process_long_option(actx, option, equal);

						if (result == NULL)
						{
							argparse_delete(actx);
							return NULL;
						}

						continue;
					}

					// Check if there is a matching short option
					option = argparse_find_short_option(actx, argument[pos]);

					if (option == NULL)
					{
						// Add the unknown option
						result = argparse_result_push(actx, ARGPARSE_RETURN_UNKNOWN_LONG_OPTION, actx->args[actx->arg_index]);
						actx->arg_index += 1;

						if (result == NULL)
						{
							argparse_delete(actx);
							return NULL;
						}

						continue;
					}
				}

				while (argument[pos] != '\0')
				{
					option = argparse_find_short_option(actx, argument[pos]);

					// Unknown options
					if (option == NULL)
					{
						result =
							argparse_result_push(actx, ARGPARSE_RETURN_UNKNOWN_SHORT_OPTION, PTR_OFFSET(actx->args[actx->arg_index], pos));
						actx->arg_index += 1;

						if (result == NULL)
						{
							argparse_delete(actx);
							return NULL;
						}

						// Goto next argument
						break;
					}

					if (option->argument_type == ARGPARSE_OPTION_ARGUMENT_NONE)
					{
						result = argparse_result_push(actx, option->return_value, NULL);

						if (result == NULL)
						{
							argparse_delete(actx);
							return NULL;
						}
					}

					if (option->argument_type == ARGPARSE_OPTION_ARGUMENT_REQUIRED)
					{
						if (argument[pos + 1] != '\0')
						{
							value = &argument[pos + 1];
							actx->arg_index += 1;
						}
						else
						{
							// Consume next argument
							value = actx->args[actx->arg_index + 1];
							actx->arg_index += 2;
						}

						result = argparse_result_push(actx, option->return_value, value);

						if (result == NULL)
						{
							argparse_delete(actx);
							return NULL;
						}

						// Always break on short options requiring an argument
						break;
					}

					pos += 1;
				}
			}
			else // if (argument[pos + 1] == '\0')
			{
				result = argparse_result_push(actx, ARGPARSE_RETURN_STDIN_OPTION, actx->args[actx->arg_index]);
				actx->arg_index += 1;

				if (result == NULL)
				{
					argparse_delete(actx);
					return NULL;
				}
			}
		}
		else // if (argument[pos] != '-')
		{
			arg_option_t *option = NULL;

			// Check if argument is a subcommand
			option = argparse_find_subcommand(actx, argument);

			if (option == NULL)
			{
				if (actx->flags & ARGPARSE_FLAG_BREAK_AT_NON_OPTION)
				{
					goto consume_remaining_args;
				}
			}

			// Processing of the subcommand will be done by another argparse_t structure.
			// Consume the subcommand and return return the upto date actx.
			result = argparse_result_push(actx, option->return_value, NULL);
			actx->arg_index += 1;

			if (result == NULL)
			{
				argparse_delete(actx);
				return NULL;
			}

			return actx;
		}
	}

consume_remaining_args:
	while (actx->arg_index < actx->arg_count)
	{
		result = argparse_result_push(actx, ARGPARSE_RETURN_NON_OPTION, actx->args[actx->arg_index]);

		if (result == NULL)
		{
			argparse_delete(actx);
			return NULL;
		}

		actx->arg_index += 1;
	}

	return actx;
}

void argparse_delete(argparse_t *actx)
{
	// Only free the result array. Rest are references.
	free(actx->results);
	free(actx);
}

arg_result_t *argparse(argparse_t *actx)
{
	if (actx->result_index == actx->result_count)
	{
		return NULL;
	}

	return &actx->results[actx->result_index++];
}
