/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef X509_MEMORY_H
#define X509_MEMORY_H

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

static inline void *zmalloc(size_t size)
{
	void *mem = NULL;

	mem = malloc(size);

	if (mem == NULL)
	{
		return NULL;
	}

	memset(mem, 0, size);

	return mem;
}

static inline void *zrealloc(void *old, size_t size)
{
	void *mem = NULL;

	mem = realloc(old, size);

	if (mem == NULL)
	{
		free(old);
		return NULL;
	}

	return mem;
}

static inline void zfree(void *mem)
{
	free(mem);
}

#endif
