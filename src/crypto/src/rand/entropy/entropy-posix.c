/*
Copyright (c) 2024 - 2025 Sibi Siddharthan

Distributed under the MIT license.
Refer to the LICENSE file at the root directory for details.
*/

#include <types.h>
#include <unused.h>

extern int getentropy(void *buffer, size_t length);

uint32_t get_entropy(void *state, void *buffer, uint32_t size)
{
	UNUSED(state);

	if (getentropy(buffer, size) < 0)
	{
		return 0;
	}

	return size;
}
