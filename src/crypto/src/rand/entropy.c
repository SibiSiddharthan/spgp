/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <string.h>
#include <intrin.h>
#include <types.h>

uint32_t get_entropy(void *buffer, size_t size)
{
	int32_t status = 0;
	size_t count = 0;
	byte_t *bp = buffer;

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
