/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_TEST_H
#define CRYPTO_TEST_H

#include <stdio.h>
#include <string.h>
#include <types.h>

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static void hash_to_hex(byte_t *hash, size_t in, char *hex, size_t out)
{
	uint64_t i = 0, j = 0;

	for (i = 0; i < in && j < out; ++i)
	{
		byte_t a, b;

		a = hash[i] / 16;
		b = hash[i] % 16;

		hex[j++] = hex_table[a];
		hex[j++] = hex_table[b];
	}
}

static int32_t check_hash(byte_t *hash, size_t size, char *expected)
{
	int32_t status;
	char hex[1025] = {0};

	hash_to_hex(hash, size, hex, 1024);

	status = memcmp(expected, hex, size * 2);

	if (status == 0)
	{
		return 0;
	}

	printf("Hash does not match.\nExpected: %s\nGot:      %s\n", expected, hex);

	return 1;
}

#endif
