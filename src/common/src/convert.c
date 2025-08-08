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

static uint32_t uint_to_hex_common(char buffer[32], uint8_t upper, uint64_t x)
{
	const char *table = upper ? hex_upper_table : hex_lower_table;
	char temp[8] = {0};
	uint8_t pos = 0;

	do
	{
		temp[pos++] = table[x & 0x0F];
		x >>= 4;

	} while (x != 0);

	for (uint8_t i = 0; i < pos; ++i)
	{
		buffer[i] = temp[pos - i - 1];
	}

	return pos;
}

uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint8_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint16_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint32_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint64_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

static uint32_t uint_to_oct_common(char buffer[32], uint64_t x)
{
	char temp[8] = {0};
	uint8_t pos = 0;

	do
	{
		temp[pos++] = (x & 0x07) + '0';
		x >>= 3;

	} while (x != 0);

	for (uint8_t i = 0; i < pos; ++i)
	{
		buffer[i] = temp[pos - i - 1];
	}

	return pos;
}

uint32_t u8_to_oct(char buffer[32], uint8_t x)
{
	return uint_to_oct_common(buffer, x);
}

uint32_t u16_to_oct(char buffer[32], uint16_t x)
{
	return uint_to_oct_common(buffer, x);
}

uint32_t u32_to_oct(char buffer[32], uint32_t x)
{
	return uint_to_oct_common(buffer, x);
}

uint32_t u64_to_oct(char buffer[32], uint64_t x)
{
	return uint_to_oct_common(buffer, x);
}

static uint32_t uint_to_bin_common(char buffer[64], uint64_t x)
{
	char temp[8] = {0};
	uint8_t pos = 0;

	do
	{
		temp[pos++] = (x & 0x1) + '0';
		x >>= 1;

	} while (x != 0);

	for (uint8_t i = 0; i < pos; ++i)
	{
		buffer[i] = temp[pos - i - 1];
	}

	return pos;
}

uint32_t u8_to_bin(char buffer[64], uint8_t x)
{
	return uint_to_oct_common(buffer, x);
}

uint32_t u16_to_bin(char buffer[64], uint16_t x)
{
	return uint_to_oct_common(buffer, x);
}

uint32_t u32_to_bin(char buffer[64], uint32_t x)
{
	return uint_to_oct_common(buffer, x);
}

uint32_t u64_to_bin(char buffer[64], uint64_t x)
{
	return uint_to_oct_common(buffer, x);
}
