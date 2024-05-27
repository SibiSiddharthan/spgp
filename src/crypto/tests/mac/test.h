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

static byte_t hex_value(char ch)
{
	switch (ch)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'a':
		return 10;
	case 'b':
		return 11;
	case 'c':
		return 12;
	case 'd':
		return 13;
	case 'e':
		return 14;
	case 'f':
		return 15;
	}

	return 255;
}

static void hex_to_block(byte_t *block, size_t size, char *hex)
{
	uint64_t i = 0, j = 0;

	for (i = 0; i < (size * 2) && j < size; i += 2)
	{
		block[j++] = hex_value(hex[i]) * 16 + hex_value(hex[i + 1]);
	}
}

static void mac_to_hex(byte_t *mac, size_t in, char *hex, size_t out)
{
	uint64_t i = 0, j = 0;

	for (i = 0; i < in && j < out; ++i)
	{
		byte_t a, b;

		a = mac[i] / 16;
		b = mac[i] % 16;

		hex[j++] = hex_table[a];
		hex[j++] = hex_table[b];
	}
}

static int32_t check_mac(byte_t *mac, size_t size, char *expected)
{
	int32_t status;
	char hex[1025] = {0};

	mac_to_hex(mac, size, hex, 1024);

	status = memcmp(expected, hex, size * 2);

	if (status == 0)
	{
		return 0;
	}

	printf("Hash does not match.\nExpected: %s\nGot:      %s\n", expected, hex);

	return 1;
}

#endif
