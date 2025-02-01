/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <string.h>
#include <intrin.h>
#include <types.h>
#include <unused.h>

uint32_t get_entropy(void *state, void *buffer, uint32_t size)
{
	uint32_t status = 0;
	uint32_t count = 0;
	byte_t *bp = buffer;

	UNUSED(state);

	while ((count + sizeof(uint64_t)) < size)
	{
		status = _rdseed64_step((uint64_t *)(bp + count));

		if (status == 0)
		{
			return count;
		}

		count += sizeof(uint64_t);
	}

	if (count < size)
	{
		uint64_t temp;

		status = _rdseed64_step(&temp);

		if (status == 0)
		{
			return count;
		}

		memcpy(bp + count, &temp, size - count);
	}

	return count;
}
