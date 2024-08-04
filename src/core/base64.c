/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <base64.h>

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

int32_t base64_encode(buffer_range_t *output, buffer_range_t *input, base64_op ops)
{
	size_t *ip, *op;
	byte_t v1, v2, v3;

	// No input
	if (input->start == input->end)
	{
		return BASE64_SUCCESS;
	}

	// Every 3 bytes from input becomes 4 bytes at output.
	while ((input->start + 3 <= input->end) && (output->start + 4 <= output->end))
	{
		ip = &input->start;
		op = &output->start;

		v1 = input->data[(*ip)++];
		v2 = input->data[(*ip)++];
		v3 = input->data[(*ip)++];

		output->data[(*op)++] = base64_encode_table[v1 >> 2];
		output->data[(*op)++] = base64_encode_table[((v1 & 0x3) << 4) + (v2 >> 4)];
		output->data[(*op)++] = base64_encode_table[((v2 & 0xf) << 2) + (v3 >> 6)];
		output->data[(*op)++] = base64_encode_table[v3 & 0x3f];
	}

	// Padding at the end
	if (ops == BASE64_FINISH)
	{
		ip = &input->start;
		op = &output->start;

		if (output->start + 4 > output->end)
		{
			return BASE64_INSUFFICIENT_BUFFER;
		}

		switch (input->end - input->start)
		{
		case 1:
			v1 = input->data[(*ip)++];

			output->data[(*op)++] = base64_encode_table[v1 >> 2];
			output->data[(*op)++] = base64_encode_table[((v1 & 0x3) << 4)];
			output->data[(*op)++] = '=';
			output->data[(*op)++] = '=';
			input->start += 2;
			break;
		case 2:
			v1 = input->data[(*ip)++];
			v2 = input->data[(*ip)++];

			output->data[(*op)++] = base64_encode_table[v1 >> 2];
			output->data[(*op)++] = base64_encode_table[((v1 & 0x3) << 4) + (v2 >> 4)];
			output->data[(*op)++] = base64_encode_table[((v2 & 0xf) << 2)];
			output->data[(*op)++] = '=';
			input->start += 1;
			break;
		}

		return BASE64_STREAM_END;
	}

	return BASE64_SUCCESS;
}

int32_t base64_decode(buffer_range_t *output, buffer_range_t *input)
{
	size_t *ip, *op;
	byte_t v1, v2, v3, v4;
	byte_t w1, w2, w3, w4;

	// No input
	if (input->start == input->end)
	{
		return BASE64_SUCCESS;
	}

	// Every 4 bytes from input becomes 3 bytes at output.
	while ((input->start + 4 <= input->end) && (output->start + 3 <= output->end))
	{
		ip = &input->start;
		op = &output->start;

		v1 = input->data[(*ip)++];
		v2 = input->data[(*ip)++];
		v3 = input->data[(*ip)++];
		v4 = input->data[(*ip)++];

		w1 = base64_decode_table[v1];
		w2 = base64_decode_table[v2];
		w3 = base64_decode_table[v3];
		w4 = base64_decode_table[v4];

		if (w1 == 255 || w2 == 255 || w3 == 255 || w4 == 255)
		{
			return BASE64_ILLEGAL_STREAM;
		}

		if (v1 == '=' || v2 == '=')
		{
			return BASE64_ILLEGAL_STREAM;
		}

		if (v3 == '=' && v4 != '=')
		{
			return BASE64_ILLEGAL_STREAM;
		}

		if (v3 != '=' && v4 != '=')
		{
			output->data[(*op)++] = (w1 << 2) + (w2 >> 4);
			output->data[(*op)++] = (w2 << 4) + (w3 >> 2);
			output->data[(*op)++] = (w3 << 6) + w4;
		}
		else
		{
			if (v3 == '=') // implies v4 == '='
			{
				output->data[(*op)++] = (w1 << 2) + (w2 >> 4);
			}
			else // v4 == '='
			{
				output->data[(*op)++] = (w1 << 2) + (w2 >> 4);
				output->data[(*op)++] = (w2 << 4) + (w3 >> 2);
			}

			return BASE64_STREAM_END;
		}
	}

	return BASE64_SUCCESS;
}
