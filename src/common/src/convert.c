/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <string.h>

static const char hex_lower_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static const char hex_upper_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

// clang-format off
static const uint8_t hex_to_nibble_table[256] = 
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,                       // 0 - 9
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // A - F
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // a - f
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};
// clang-format on

uint32_t print_hex(const char *table, char *buffer, uint32_t buffer_size, void *data, uint32_t data_size)
{
	uint32_t pos = 0;

	for (uint32_t i = 0; i < data_size; ++i)
	{
		uint8_t a, b;

		a = ((uint8_t *)data)[i] / 16;
		b = ((uint8_t *)data)[i] % 16;

		buffer[pos++] = table[a];
		buffer[pos++] = table[b];
	}

	return pos;
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

static uint64_t uint_from_hex_common(void *buffer, uint8_t size)
{
	uint8_t *in = buffer;
	uint64_t result = 0;
	uint8_t nibble = 0;

	while (size--)
	{
		if ((nibble = hex_to_nibble_table[*in++]) == 255)
		{
			break;
		}

		result = (result << 4) + nibble;
	}

	return result;
}

uint32_t u8_to_hex(char buffer[32], uint8_t upper, uint8_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

uint32_t u16_to_hex(char buffer[32], uint8_t upper, uint16_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

uint32_t u32_to_hex(char buffer[32], uint8_t upper, uint32_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

uint32_t u64_to_hex(char buffer[32], uint8_t upper, uint64_t x)
{
	return uint_to_hex_common(buffer, upper, x);
}

uint8_t u8_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

uint16_t u16_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

uint32_t u32_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
}

uint64_t u64_from_hex(void *buffer, uint8_t size)
{
	return uint_from_hex_common(buffer, size);
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
	return uint_to_bin_common(buffer, x);
}

uint32_t u16_to_bin(char buffer[64], uint16_t x)
{
	return uint_to_bin_common(buffer, x);
}

uint32_t u32_to_bin(char buffer[64], uint32_t x)
{
	return uint_to_bin_common(buffer, x);
}

uint32_t u64_to_bin(char buffer[64], uint64_t x)
{
	return uint_to_bin_common(buffer, x);
}

static uint32_t uint_to_dec_common(char buffer[32], uint64_t x)
{
	char temp[8] = {0};
	uint8_t pos = 0;

	do
	{
		temp[pos++] = (x % 10) + '0';
		x /= 10;

	} while (x != 0);

	for (uint8_t i = 0; i < pos; ++i)
	{
		buffer[i] = temp[pos - i - 1];
	}

	return pos;
}

uint32_t u8_to_dec(char buffer[32], uint8_t x)
{
	return uint_to_dec_common(buffer, x);
}

uint32_t u16_to_dec(char buffer[32], uint16_t x)
{
	return uint_to_dec_common(buffer, x);
}

uint32_t u32_to_dec(char buffer[32], uint32_t x)
{
	return uint_to_dec_common(buffer, x);
}

uint32_t u64_to_dec(char buffer[32], uint64_t x)
{
	return uint_to_dec_common(buffer, x);
}

static uint32_t int_to_dec_common(char buffer[32], int64_t x)
{
	uint8_t minus = 0;

	if (x < 0)
	{
		x = ~x + 1;
		minus = 1;
		*buffer++ = '-';
	}

	return uint_to_dec_common(buffer, x) + minus;
}

uint32_t i8_to_dec(char buffer[32], int8_t x)
{
	if (x == INT8_MIN)
	{
		memcpy(buffer, "-128", 4);
		return 4;
	}

	return int_to_dec_common(buffer, x);
}

uint32_t i16_to_dec(char buffer[32], int16_t x)
{
	if (x == INT16_MIN)
	{
		memcpy(buffer, "-32768", 6);
		return 6;
	}

	return int_to_dec_common(buffer, x);
}

uint32_t i32_to_dec(char buffer[32], int32_t x)
{
	if (x == INT32_MIN)
	{
		memcpy(buffer, "-2147483648", 11);
		return 11;
	}

	return int_to_dec_common(buffer, x);
}

uint32_t i64_to_dec(char buffer[32], int64_t x)
{
	if (x == INT64_MIN)
	{
		memcpy(buffer, "-9223372036854775808", 20);
		return 20;
	}

	return int_to_dec_common(buffer, x);
}
