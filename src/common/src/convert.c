/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>

static const char hex_lower_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static const char hex_upper_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

static inline void do_u8_hex_to_char(char *buffer, char *table, uint8_t x)
{
	uint8_t a = 0, b = 0;

	a = x / 16;
	b = x % 16;

	*buffer++ = table[a];
	*buffer++ = table[b];
}

static uint32_t do_uint_to_hex(char buffer[32], uint8_t upper, uint64_t x)
{
	const char *table = upper ? hex_upper_table : hex_lower_table;
	char temp[8] = {0};
	uint8_t pos = 0;

	while (x != 0)
	{
		temp[pos++] = table[x & 0x0F];
		x >>= 4;
	}

	if (temp[pos - 1] == '0')
	{
		pos--;
	}

	for (uint8_t i = 0; i < pos; ++i)
	{
		buffer[i] = temp[pos - i - 1];
	}

	return pos;
}

static uint32_t do_uint_to_oct(char buffer[32], uint64_t x)
{
	char temp[8] = {0};
	uint8_t pos = 0;

	while (x != 0)
	{
		temp[pos++] = (x & 0x07) + '0';
		x >>= 3;
	}

	if (temp[pos - 1] == '0')
	{
		pos--;
	}

	for (uint8_t i = 0; i < pos; ++i)
	{
		buffer[i] = temp[pos - i - 1];
	}

	return pos;
}

uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint8_t x)
{
	return do_uint_hex_to_char(buffer, upper, x);
}

uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint16_t x)
{
	return do_uint_hex_to_char(buffer, upper, x);
}

uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint32_t x)
{
	return do_uint_hex_to_char(buffer, upper, x);
}

uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint64_t x)
{
	return do_uint_hex_to_char(buffer, upper, x);
}
