/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_BUFFER_H
#define SPGP_BUFFER_H

#include <types.h>

typedef struct _buffer_t
{
	byte_t *data;
	size_t size;
	size_t capacity;
} buffer_t;

typedef struct _buffer_range_t
{
	byte_t *data;
	size_t start;
	size_t end;
} buffer_range_t;


#endif
