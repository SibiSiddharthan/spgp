/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdint.h>
#include <string.h>
#include <ptr.h>

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

	while (size--)
	{
		result = (result << 4) + hex_to_nibble_table[*in++];
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

static uint64_t uint_from_oct_common(void *buffer, uint8_t size)
{
	uint8_t *in = buffer;
	uint64_t result = 0;

	while (size--)
	{
		result = (result << 3) + (*in++ - '0');
	}

	return result;
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

uint8_t u8_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

uint16_t u16_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

uint32_t u32_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
}

uint64_t u64_from_oct(void *buffer, uint8_t size)
{
	return uint_from_oct_common(buffer, size);
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

static uint64_t uint_from_bin_common(void *buffer, uint8_t size)
{
	uint8_t *in = buffer;
	uint64_t result = 0;

	while (size--)
	{
		result = (result << 1) + (*in++ - '0');
	}

	return result;
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

uint8_t u8_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

uint16_t u16_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

uint32_t u32_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
}

uint64_t u64_from_bin(void *buffer, uint8_t size)
{
	return uint_from_bin_common(buffer, size);
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

static uint64_t uint_from_dec_common(void *buffer, uint8_t size)
{
	uint8_t *in = buffer;
	uint64_t result = 0;

	while (size--)
	{
		result = (result * 10) + (*in++ - '0');
	}

	return result;
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

uint8_t u8_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

uint16_t u16_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

uint32_t u32_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

uint64_t u64_from_dec(void *buffer, uint8_t size)
{
	return uint_from_dec_common(buffer, size);
}

static int64_t int_to_dec_common(char buffer[32], int64_t x)
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

static uint32_t int_from_dec_common(void *buffer, uint8_t size)
{
	uint8_t *in = buffer;
	int64_t result = 0;
	uint8_t minus = 0;

	if (*in == '-')
	{
		minus = 1;
		size--;
		in++;
	}

	while (size--)
	{
		if (minus)
		{
			result = (result * 10) - (*in++ - '0');
		}
		else
		{
			result = (result * 10) + (*in++ - '0');
		}
	}

	return result;
}

uint32_t i8_to_dec(char buffer[32], int8_t x)
{
	return int_to_dec_common(buffer, x);
}

uint32_t i16_to_dec(char buffer[32], int16_t x)
{
	return int_to_dec_common(buffer, x);
}

uint32_t i32_to_dec(char buffer[32], int32_t x)
{
	return int_to_dec_common(buffer, x);
}

uint32_t i64_to_dec(char buffer[32], int64_t x)
{
	// Catch only this conversion, rest of them will work due to type promotion.
	if (x == INT64_MIN)
	{
		memcpy(buffer, "-9223372036854775808", 20);
		return 20;
	}

	return int_to_dec_common(buffer, x);
}

int8_t i8_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

int16_t i16_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

int32_t i32_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

int64_t i64_from_dec(void *buffer, uint8_t size)
{
	return int_from_dec_common(buffer, size);
}

#define FLOAT32_EXP_BIAS 127
#define FLOAT64_EXP_BIAS 1023

uint32_t float32_to_hex(char buffer[64], uint8_t upper, float x)
{
	uint32_t v = *((uint32_t *)&x);
	uint8_t exponent = 0;
	uint32_t mantissa = 0;
	uint32_t pos = 0;
	uint8_t sign = 0;

	sign = (v >> 31) & 0x1;             // 1 bit
	exponent = ((v << 1) >> 24) & 0xFF; // 8 bits
	mantissa = v & 0x7FF;               // 23 bits

	// Sign
	if (sign)
	{
		buffer[pos++] = '-';
	}

	// Form '0x1.' or '0x0.'
	buffer[pos++] = '0';
	buffer[pos++] = upper ? 'X' : 'x';

	if (exponent != 0)
	{
		// Normal
		buffer[pos++] = '1';
	}
	else
	{
		// Subnormal
		buffer[pos++] = '0';
	}

	buffer[pos++] = '.';

	// Mantissa
	pos += uint_to_hex_common(buffer + pos, upper, mantissa);

	// Exponent
	buffer[pos++] = upper ? 'P' : 'p';

	if (exponent >= FLOAT32_EXP_BIAS)
	{
		buffer[pos++] = '+';
		pos += uint_to_dec_common(buffer + pos, exponent - FLOAT32_EXP_BIAS);
	}
	else
	{
		buffer[pos++] = '-';
		pos += uint_to_dec_common(buffer + pos, FLOAT32_EXP_BIAS - exponent);
	}

	return pos;
}

uint32_t float64_to_hex(char buffer[64], uint8_t upper, double x)
{
	uint64_t v = *((uint64_t *)&x);
	uint8_t exponent = 0;
	uint32_t mantissa = 0;
	uint32_t pos = 0;
	uint8_t sign = 0;

	sign = (v >> 63) & 0x1;              // 1 bit
	exponent = ((v << 1) >> 53) & 0x7FF; // 11 bits
	mantissa = v & 0x1FFFFFFFFFFFFF;     // 52 bits

	// Sign
	if (sign)
	{
		buffer[pos++] = '-';
	}

	// Form '0x1.' or '0x0.'
	buffer[pos++] = '0';
	buffer[pos++] = upper ? 'X' : 'x';

	if (exponent != 0)
	{
		// Normal
		buffer[pos++] = '1';
	}
	else
	{
		// Subnormal
		buffer[pos++] = '0';
	}

	buffer[pos++] = '.';

	// Mantissa
	pos += uint_to_hex_common(buffer + pos, upper, mantissa);

	// Exponent
	buffer[pos++] = upper ? 'P' : 'p';

	if (exponent >= FLOAT64_EXP_BIAS)
	{
		buffer[pos++] = '+';
		pos += uint_to_dec_common(buffer + pos, exponent - FLOAT64_EXP_BIAS);
	}
	else
	{
		buffer[pos++] = '-';
		pos += uint_to_dec_common(buffer + pos, FLOAT64_EXP_BIAS - exponent);
	}

	return pos;
}

uint32_t utf8_octets(uint32_t codepoint)
{
	if (codepoint <= 0x7F)
	{
		return 1;
	}

	if (codepoint >= 0x80 && codepoint <= 0x07FF)
	{
		return 2;
	}

	if (codepoint >= 0x800 && codepoint <= 0xFFFF)
	{
		return 3;
	}

	if (codepoint >= 0x10000 && codepoint <= 0x10FFFF)
	{
		return 4;
	}

	return 0;
}

uint32_t utf8_encode(char buffer[32], uint32_t codepoint)
{
	if (codepoint <= 0x7F)
	{
		*buffer++ = codepoint & 0x7F; // 7 bits

		return 1;
	}

	if (codepoint >= 0x80 && codepoint <= 0x07FF)
	{
		*buffer++ = 0xC0 | ((codepoint >> 6) & 0x1F); // 5 bits
		*buffer++ = 0x80 | (codepoint & 0x3F);        // 6 bits

		return 2;
	}

	if (codepoint >= 0x800 && codepoint <= 0xFFFF)
	{
		*buffer++ = 0xE0 | ((codepoint >> 12) & 0x0F); // 4 bits
		*buffer++ = 0x80 | ((codepoint >> 6) & 0x3F);  // 6 bits
		*buffer++ = 0x80 | (codepoint & 0x3F);         // 6 bits

		return 3;
	}

	if (codepoint >= 0x10000 && codepoint <= 0x10FFFF)
	{
		*buffer++ = 0xF0 | ((codepoint >> 18) & 0x07); // 3 bits
		*buffer++ = 0x80 | ((codepoint >> 12) & 0x3F); // 6 bits
		*buffer++ = 0x80 | ((codepoint >> 6) & 0x3F);  // 6 bits
		*buffer++ = 0x80 | (codepoint & 0x3F);         // 6 bits

		return 4;
	}

	// Illegal Codepoint
	return 0;
}

uint32_t utf8_decode(void *buffer, uint8_t size, uint32_t *codepoint)
{
	uint8_t *in = buffer;
	uint8_t byte = 0;

	if (size == 0)
	{
		return 0;
	}

	byte = *in++;
	*codepoint = 0;

	if (byte <= 0x7F)
	{
		*codepoint = byte;
		return 1;
	}

	if ((byte & 0xE0) == 0xC0) // Ensure 11'0'xxxxx
	{
		if (size < 2)
		{
			return 0;
		}

		*codepoint |= (byte & 0x1F) << 6;
		byte = *in++;

		// Illegal Sequence
		if ((byte & 0xC0) != 0x80)
		{
			return 0;
		}

		*codepoint |= (byte & 0x3F);

		// Invalid Encoding
		if (*codepoint < 0x80)
		{
			return 0;
		}

		return 2;
	}

	if ((byte & 0xF0) == 0xE0) // Ensure 111'0'xxxx
	{
		if (size < 3)
		{
			return 0;
		}

		*codepoint |= (byte & 0x0F) << 12;
		byte = *in++;

		// Illegal Sequence
		if ((byte & 0xC0) != 0x80)
		{
			return 0;
		}

		*codepoint |= (byte & 0x3F) << 6;
		byte = *in++;

		// Illegal Sequence
		if ((byte & 0xC0) != 0x80)
		{
			return 0;
		}

		*codepoint |= (byte & 0x3F);

		// Surrogate pairs (Invalid codepoints)
		if (*codepoint >= 0xD800 && *codepoint <= 0xDFFF)
		{
			return 0;
		}

		// Invalid Encoding
		if (*codepoint < 0x800)
		{
			return 0;
		}

		return 3;
	}

	if ((byte & 0xF8) == 0xF0) // Ensure 1111'0'xxx
	{
		if (size < 4)
		{
			return 0;
		}

		*codepoint |= (byte & 0x07) << 18;
		byte = *in++;

		// Illegal Sequence
		if ((byte & 0xC0) != 0x80)
		{
			return 0;
		}

		*codepoint |= (byte & 0x3F) << 12;
		byte = *in++;

		// Illegal Sequence
		if ((byte & 0xC0) != 0x80)
		{
			return 0;
		}

		*codepoint |= (byte & 0x3F) << 6;
		byte = *in++;

		// Illegal Sequence
		if ((byte & 0xC0) != 0x80)
		{
			return 0;
		}

		*codepoint |= (byte & 0x3F);

		// Invalid Encoding (also catches surrogate pairs)
		if (*codepoint < 0x10000)
		{
			return 0;
		}

		return 4;
	}

	return 0;
}

uint32_t utf16_octets(uint32_t codepoint)
{
	if (codepoint <= 0xFFFF)
	{
		return 2;
	}

	if (codepoint <= 0x10FFFF)
	{
		return 4;
	}

	return 0;
}

uint32_t utf16_encode(char buffer[32], uint32_t codepoint)
{
	uint32_t v = 0;
	uint32_t enc = 0;

	// Invalid Codepoint
	if (codepoint > 0x10FFFF)
	{
		return 0;
	}

	if (codepoint <= 0xFFFF)
	{
		memcpy(buffer, &codepoint, 2);
		return 2;
	}

	v = codepoint - 0x10000;

	// High 16 bits
	enc |= (0xD800 | ((v >> 10) & 0x3FF)) << 16;

	// Low 16 bits
	enc |= 0xDC00 | (v & 0x3FF);

	memcpy(buffer, &enc, 4);

	return 4;
}

uint32_t utf16_decode(void *buffer, uint8_t size, uint32_t *codepoint)
{
	uint16_t *in = buffer;
	uint16_t high = 0;
	uint16_t low = 0;

	if (size < 2)
	{
		return 0;
	}

	*codepoint = 0;
	high = *in++;

	if (high < 0xD800 || high > 0xDFFF)
	{
		*codepoint = high;
		return 2;
	}

	if (high >= 0xD800 && high <= 0xDBFF)
	{
		if (size < 4)
		{
			return 0;
		}

		low = *in++;

		if (low >= 0xDC00 && low <= 0xDFFF)
		{
			*codepoint |= (high & 0x3FF) << 16;
			*codepoint |= low & 0x3FF;

			// Invalid Encoding (also catches surrogate pairs)
			if (*codepoint < 0x10000)
			{
				return 0;
			}

			return 4;
		}
	}

	// Invalid Sequence
	return 0;
}

void utf8_string_utf16_string(void *utf16, size_t *utf16_size, void *utf8, size_t *utf8_size)
{
	size_t in_pos = 0;
	size_t out_pos = 0;
	uint32_t result = 0;
	uint32_t codepoint = 0;

	while (utf8_size != 0)
	{
		result = utf8_decode(PTR_OFFSET(utf8, in_pos), *utf8_size - in_pos, &codepoint);

		if (result == 0)
		{
			goto finish;
		}

		if ((out_pos + utf16_octets(codepoint)) > *utf16_size)
		{
			goto finish;
		}

		out_pos += utf16_encode(PTR_OFFSET(utf16, out_pos), codepoint);
		in_pos += result;
	}

finish:
	*utf8_size = in_pos;
	*utf16_size = out_pos;

	return;
}

void utf16_string_utf8_string(void *utf8, size_t *utf8_size, void *utf16, size_t *utf16_size)
{
	size_t in_pos = 0;
	size_t out_pos = 0;
	uint32_t result = 0;
	uint32_t codepoint = 0;

	while (utf8_size != 0)
	{
		result = utf16_decode(PTR_OFFSET(utf16, in_pos), *utf16_size - in_pos, &codepoint);

		if (result == 0)
		{
			goto finish;
		}

		if ((out_pos + utf8_octets(codepoint)) > *utf8_size)
		{
			goto finish;
		}

		out_pos += utf8_encode(PTR_OFFSET(utf8, out_pos), codepoint);
		in_pos += result;
	}

finish:
	*utf8_size = out_pos;
	*utf16_size = in_pos;

	return;
}
