/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BUFFER_H
#define CRYPTO_BUFFER_H

#include <types.h>

typedef struct _buffer_t
{
	byte_t *data;
	size_t pos;
	size_t size;
} buffer_t;

#endif
