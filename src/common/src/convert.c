/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>

static const char hex_lower_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static const char hex_upper_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

static inline uint8_t do_u8_hex_to_char(char *buffer, char *table, uint8_t truncate, uint8_t x)
{
	uint8_t a = 0, b = 0;

	a = x / 16;
	b = x % 16;

	if (truncate)
	{
		if (a == 0)
		{
			*buffer++ = table[b];
			return 1;
		}
		else
		{
			*buffer++ = table[a];
			*buffer++ = table[b];
		}
	}
	else
	{
		*buffer++ = table[a];
		*buffer++ = table[b];
	}

	return 2;
}

uint32_t u32_hex_to_char(char buffer[8], uint32_t x, uint8_t upper)
{
	const char *table = upper ? hex_upper_table : hex_lower_table;
	uint8_t truncate = 1;

	uint8_t temp = 0;
	uint8_t pos = 0;

	if ((temp = (x >> 24) & 0xFF) > 0)
	{
		pos += do_u8_hex_to_char(buffer + pos, table, truncate, temp);
		truncate = 0;
	}

	if ((temp = (x >> 16) & 0xFF) > 0)
	{
		pos += do_u8_hex_to_char(buffer + pos, table, truncate, temp);
		truncate = 0;
	}

	if ((temp = (x >> 8) & 0xFF) > 0)
	{
		pos += do_u8_hex_to_char(buffer + pos, table, truncate, temp);
		truncate = 0;
	}

	if ((temp = (x >> 0) & 0xFF) > 0)
	{
		pos += do_u8_hex_to_char(buffer + pos, table, truncate, temp);
		truncate = 0;
	}

	return pos;
}
