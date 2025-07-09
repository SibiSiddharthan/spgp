/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp/base64.h>

static byte_t base64_encode_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
									   'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
									   'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
									   'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

// clang-format off
static byte_t base64_decode_table[] = 
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62 /* + */, 255, 255, 255, 63 /* / */,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, /* 0-9 */
	255, 255, 255, 0 /* = */, 255, 255, 255,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, /* A-Z */
	255, 255, 255, 255, 255, 255,
	26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,	42, 43, 44, 45, 46, 47, 48, 49, 50, 51, /* a-z */
	255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,	255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};
// clang-format on

size_t base64_encode(void *input, size_t input_size, void *output, size_t output_size)
{
	byte_t *in = input;
	byte_t *out = output;

	size_t input_pos = 0;
	size_t output_pos = 0;

	byte_t v1 = 0, v2 = 0, v3 = 0;

	if (output_size < BASE64_ENCODE_SIZE(input_size))
	{
		return 0;
	}

	// Every 3 bytes from input becomes 4 bytes at output.
	while (input_pos + 3 <= input_size)
	{
		v1 = in[input_pos++];
		v2 = in[input_pos++];
		v3 = in[input_pos++];

		out[output_pos++] = base64_encode_table[v1 >> 2];
		out[output_pos++] = base64_encode_table[((v1 & 0x3) << 4) + (v2 >> 4)];
		out[output_pos++] = base64_encode_table[((v2 & 0xf) << 2) + (v3 >> 6)];
		out[output_pos++] = base64_encode_table[v3 & 0x3f];
	}

	if (input_pos < input_size)
	{
		// Padding at the end
		switch (input_size - input_pos)
		{
		case 1:
		{
			v1 = in[input_pos++];

			out[output_pos++] = base64_encode_table[v1 >> 2];
			out[output_pos++] = base64_encode_table[((v1 & 0x3) << 4)];
			out[output_pos++] = '=';
			out[output_pos++] = '=';
		}
		break;
		case 2:
		{
			v1 = in[input_pos++];
			v2 = in[input_pos++];

			out[output_pos++] = base64_encode_table[v1 >> 2];
			out[output_pos++] = base64_encode_table[((v1 & 0x3) << 4) + (v2 >> 4)];
			out[output_pos++] = base64_encode_table[((v2 & 0xf) << 2)];
			out[output_pos++] = '=';
		}
		break;
		}
	}

	return BASE64_ENCODE_SIZE(input_size);
}

size_t base64_decode(void *input, size_t input_size, void *output, size_t output_size)
{
	byte_t *in = input;
	byte_t *out = output;

	size_t input_pos = 0;
	size_t output_pos = 0;

	byte_t v1 = 0, v2 = 0, v3 = 0, v4 = 0;
	byte_t w1 = 0, w2 = 0, w3 = 0, w4 = 0;

	if (input_size % 4 != 0)
	{
		return 0;
	}

	if (output_size < BASE64_DECODE_SIZE(input_size))
	{
		return 0;
	}

	// Every 4 bytes from input becomes 3 bytes at output.
	while (input_pos < input_size)
	{
		v1 = in[input_pos++];
		v2 = in[input_pos++];
		v3 = in[input_pos++];
		v4 = in[input_pos++];

		w1 = base64_decode_table[v1];
		w2 = base64_decode_table[v2];
		w3 = base64_decode_table[v3];
		w4 = base64_decode_table[v4];

		if (w1 == 255 || w2 == 255 || w3 == 255 || w4 == 255)
		{
			return 0;
		}

		if (v1 == '=' || v2 == '=')
		{
			return output_pos;
		}

		if (v3 == '=' && v4 != '=')
		{
			return output_pos;
		}

		if (v3 != '=' && v4 != '=')
		{
			out[output_pos++] = (w1 << 2) + (w2 >> 4);
			out[output_pos++] = (w2 << 4) + (w3 >> 2);
			out[output_pos++] = (w3 << 6) + w4;
		}
		else
		{
			if (v3 == '=') // implies v4 == '='
			{
				out[output_pos++] = (w1 << 2) + (w2 >> 4);
			}
			else // v4 == '='
			{
				out[output_pos++] = (w1 << 2) + (w2 >> 4);
				out[output_pos++] = (w2 << 4) + (w3 >> 2);
			}
		}
	}

	return output_pos;
}
