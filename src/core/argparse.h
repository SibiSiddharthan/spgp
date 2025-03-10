/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_ARGPARSE_H
#define SPGP_ARGPARSE_H

#include <spgp.h>

// Option Flags
#define ARGPARSE_FLAG_SKIP_FIRST_ARGUMENT 0x1
#define ARGPARSE_FLAG_BREAK_AT_NON_OPTION 0x2
#define ARGPARSE_FLAG_ALLOW_LONG_ONLY     0x4

// Special Return Codes
#define ARGPARSE_RETURN_NON_OPTION           -1
#define ARGPARSE_RETURN_STDIN_OPTION         -2
#define ARGPARSE_RETURN_UNKNOWN_SHORT_OPTION -3
#define ARGPARSE_RETURN_UNKNOWN_LONG_OPTION  -4

// Argument Types
typedef enum _option_type
{
	ARGPARSE_OPTION_ARGUMENT_NONE = 0,
	ARGPARSE_OPTION_ARGUMENT_REQUIRED = 1,
	ARGPARSE_OPTION_ARGUMENT_OPTIONAL = 2,
	ARGPARSE_OPTION_SUBCOMMAND = 3
} option_type;

typedef struct _arg_option_t
{
	char *long_option;
	char short_option;
	byte_t argument_type;
	uint16_t return_value;
} arg_option_t;

typedef struct _arg_result_t
{
	uint32_t value;
	void *data;
} arg_result_t;

typedef struct _argparse_t
{
	uint32_t flags;

	uint32_t arg_count;
	uint32_t arg_index;
	void **args;

	uint32_t option_count;
	arg_option_t *options;

	uint32_t result_capacity;
	uint32_t result_count;
	uint32_t result_index;
	arg_result_t *results;
} argparse_t;

argparse_t *argparse_new(uint32_t arg_count, void **args, uint32_t option_count, arg_option_t *options, uint32_t flags);
void argparse_delete(argparse_t *actx);

arg_result_t *argparse(argparse_t *actx);

#endif
