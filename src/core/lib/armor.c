/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
#include <armor.h>
#include <base64.h>
#include <crc24.h>

#include <stdlib.h>
#include <string.h>

// Refer RFC 9580 - OpenPGP, Section 6.2 Forming ASCII Armor, Section 7 Cleartext Signature Framework

static uint16_t trimline(byte_t *line, uint16_t line_size)
{
	while (line_size > 0)
	{
		line_size -= 1;

		if (line[line_size] == ' ' || line[line_size] == '\t')
		{
			continue;
		}

		return line_size + 1;
	}

	return 0;
}

static void *check_marker_begin(armor_marker *markers, uint16_t count, byte_t *line, uint16_t line_size)
{
	for (uint16_t i = 0; i < count; ++i)
	{
		if (markers[i].header_line_size == (line_size - 10) && memcmp(markers[i].header_line, line + 5, markers[i].header_line_size) == 0)
		{
			return &markers[i];
		}
	}

	return NULL;
}

static void *check_marker_end(armor_marker *marker, byte_t *line, uint16_t line_size)
{
	if (marker->trailer_line_size == (line_size - 10) && memcmp(marker->trailer_line, line + 5, marker->trailer_line_size) == 0)
	{
		return marker;
	}

	return NULL;
}

armor_status armor_read(armor_options *options, armor_marker *markers, uint16_t count, void *input, uint32_t *input_size, void *output,
						uint32_t *output_size)
{
	void *result = NULL;
	buffer_t in = {.pos = 0, .size = *input_size, .capacity = *input_size, .data = input};

	byte_t *out = output;
	uint32_t output_pos = 0;

	byte_t line_buffer[1024] = {0};
	uint16_t line_size = 0;
	uint16_t trimmed_line_size = 0;

	byte_t base64_buffer[64] = {0};
	uint16_t base64_line_size = 64;
	uint16_t base64_remaining = 0;
	size_t base64_result = 0;

	byte_t data_started = 0;
	byte_t crc_found = 0;

	uint32_t actual_crc = crc24_init();
	uint32_t expected_crc = 0;

	options->marker = NULL;
	options->headers = NULL;
	options->headers_size = 0;

	while (1)
	{
		if (in.pos == in.size)
		{
			break;
		}

		line_size = readline(&in, line_buffer, 1024);

		if (line_size == 1024)
		{
			return ARMOR_LINE_TOO_BIG;
		}

		trimmed_line_size = trimline(line_buffer, line_size);

		if (trimmed_line_size == 0)
		{
			if (data_started)
			{
				return ARMOR_MALFORMED_DATA;
			}

			if (options->marker != NULL && options->flags & (ARMOR_SCAN_HEADERS | ARMOR_EMPTY_LINE))
			{
				data_started = 1;
			}

			continue;
		}

		// Find the block
		if (memcmp(line_buffer, "-----", 5) == 0 && memcmp(line_buffer + (trimmed_line_size - 5), "-----", 5) == 0)
		{
			if (options->marker == NULL)
			{
				result = check_marker_begin(markers, count, line_buffer, trimmed_line_size);

				if (result == NULL)
				{
					if ((options->flags & ARMOR_IGNORE_UNKNOWN_MARKERS) == 0)
					{
						// Unread the line so that the caller can read the line again.
						*input_size = in.pos - (line_size + 1 + (in.data[in.pos - 2] == '\r'));

						// Place the marker in the result
						options->unknown_header_size = trimmed_line_size - 10;
						memcpy(options->unknown_header, &line_buffer[5], MIN(trimmed_line_size - 10, 64));

						return ARMOR_UNKOWN_MARKER;
					}

					continue;
				}

				options->marker = result;
				continue;
			}
			else
			{
				result = check_marker_end(options->marker, line_buffer, trimmed_line_size);

				if (result == NULL)
				{
					return ARMOR_MARKER_MISMATCH;
				}

				// Decode last of the data
				if (base64_remaining > 0)
				{
					base64_result = base64_decode(base64_buffer, base64_remaining, out + output_pos, *output_size - output_pos);

					if (base64_result != BASE64_DECODE_SIZE(base64_remaining))
					{
						if ((BASE64_DECODE_SIZE(base64_remaining) - base64_result) > 2)
						{
							return ARMOR_MALFORMED_DATA;
						}
					}

					if (options->flags & ARMOR_CHECKSUM_CRC24)
					{
						actual_crc = crc24_update(actual_crc, out + output_pos, base64_result);
					}

					base64_remaining = 0;
					output_pos += base64_result;
				}

				goto end;
			}
		}

		// Properly armored texts will not enter this if condition.
		if (crc_found)
		{
			return ARMOR_MALFORMED_DATA;
		}

		if (options->marker == NULL)
		{
			continue;
		}

		// Read data
		if (data_started == 0)
		{
			if (options->flags & ARMOR_SCAN_HEADERS)
			{
				result = memchr(line_buffer, ':', trimmed_line_size);

				if (result != NULL)
				{
					uint16_t offset = options->headers_size;

					options->headers_size += trimmed_line_size + 1;
					options->headers = realloc(options->headers, options->headers_size);

					if (options->headers == NULL)
					{
						return ARMOR_NO_MEMORY;
					}

					memcpy(options->headers + offset, line_buffer, trimmed_line_size);
					options->headers[options->headers_size - 1] = '\0';

					// Read another header
					continue;
				}
			}

			data_started = 1;
		}
		else
		{
			if (options->flags & ARMOR_CHECKSUM_CRC24)
			{
				// Check CRC
				if (line_buffer[0] == '=' && trimmed_line_size == 5)
				{
					base64_decode(line_buffer + 1, 4, &expected_crc, 3);
					crc_found = 1;

					continue;
				}
			}
		}

		// Decode the data
		while (trimmed_line_size != 0)
		{
			uint16_t copy_size = MIN(base64_line_size - base64_remaining, trimmed_line_size);

			memcpy(base64_buffer + base64_remaining, line_buffer, copy_size);
			trimmed_line_size -= copy_size;
			base64_remaining += copy_size;

			if (base64_remaining == base64_line_size)
			{
				base64_result = base64_decode(base64_buffer, base64_line_size, out + output_pos, *output_size - output_pos);

				if (base64_result != BASE64_DECODE_SIZE(base64_line_size))
				{
					if ((BASE64_DECODE_SIZE(base64_line_size) - base64_result) > 2)
					{
						return ARMOR_MALFORMED_DATA;
					}
				}

				if (options->flags & ARMOR_CHECKSUM_CRC24)
				{
					actual_crc = crc24_update(actual_crc, out + output_pos, base64_result);
				}

				base64_remaining = 0;
				output_pos += base64_result;
			}
		}
	}

end:
	*input_size = in.pos;
	*output_size = output_pos;

	if (crc_found)
	{
		actual_crc = crc24_final(actual_crc);

		if (actual_crc != expected_crc)
		{
			return ARMOR_CRC_MISMATCH;
		}
	}

	return ARMOR_SUCCESS;
}

armor_status armor_write(armor_options *options, void *input, uint32_t input_size, void *output, uint32_t *output_size)
{
	size_t required_size = 0;
	size_t line_count = 0;
	byte_t crlf = 0;

	buffer_t out = {.pos = 0, .size = *output_size, .capacity = *output_size, .data = output};
	byte_t *in = input;
	uint32_t input_pos = 0;

	byte_t base64_line[64] = {0};
	uint32_t crc = 0;

	// Armor Structure
	// -----ARMOR HEADER-----
	// Optional Headers
	// Empty Line
	// Data
	// Optional Checksum
	// -----ARMOR FOOTER-----

	// Header and Trailer
	required_size += 20 + options->marker->header_line_size + options->marker->trailer_line_size;
	line_count += 2;

	// Optional headers
	if (options->headers_size > 0)
	{
		for (uint16_t i = 0; i < options->headers_size; ++i)
		{
			if (options->headers[i] == '\0')
			{
				line_count += 1;
			}
		}

		required_size += options->headers_size - line_count;
	}

	// Empty Line
	if (options->flags & ARMOR_EMPTY_LINE)
	{
		line_count += 1;
	}

	// Checksum
	if (options->flags & ARMOR_CHECKSUM_CRC24)
	{
		required_size += 5;
		line_count += 1;
	}

	// Data
	required_size += BASE64_ENCODE_SIZE(input_size);
	line_count += CEIL_DIV(input_size, 48);

	if (options->flags & ARMOR_CRLF_ENDING)
	{
		required_size += line_count * 2;
		crlf = 1;
	}
	else
	{
		required_size += line_count;
	}

	// Check if enough buffer is available
	if (*output_size < required_size)
	{
		if (required_size > ((uint64_t)1 << 32))
		{
			return ARMOR_INPUT_TOO_BIG;
		}

		*output_size = (uint32_t)required_size;
		return ARMOR_BUFFER_TOO_SMALL;
	}

	// Write the header line
	writen(&out, "-----", 5);
	writen(&out, options->marker->header_line, options->marker->header_line_size);
	writen(&out, "-----", 5);
	writeline(&out, NULL, 0, crlf);

	// Headers
	if (options->headers_size > 0)
	{
		uint16_t start = 0;

		for (uint16_t i = 0; i < options->headers_size; ++i)
		{
			if (options->headers[i] == '\0')
			{
				writeline(&out, options->headers + start, i - start, crlf);
				start = i + 1;
			}
		}
	}

	// Empty Line
	if (options->flags & ARMOR_EMPTY_LINE)
	{
		writeline(&out, NULL, 0, crlf);
	}

	// Data (64 columns)
	byte_t base64_insize = 0;

	if (options->flags & ARMOR_CHECKSUM_CRC24)
	{
		crc = crc24_init();
	}

	while (input_pos < input_size)
	{
		base64_insize = MIN(48, input_size - input_pos);
		base64_encode(in + input_pos, base64_insize, base64_line, BASE64_ENCODE_SIZE(base64_insize));
		writeline(&out, base64_line, BASE64_ENCODE_SIZE(base64_insize), crlf);
		input_pos += base64_insize;
	}

	// Checksum
	if (options->flags & ARMOR_CHECKSUM_CRC24)
	{
		crc = crc24_init();
		crc = crc24_update(crc, input, input_size);
		crc = crc24_final(crc);

		base64_line[0] = '=';

		base64_encode(&crc, 3, base64_line + 1, BASE64_ENCODE_SIZE(3));
		writeline(&out, base64_line, BASE64_ENCODE_SIZE(3) + 1, crlf);
	}

	// Write the trailer line
	writen(&out, "-----", 5);
	writen(&out, options->marker->trailer_line, options->marker->trailer_line_size);
	writen(&out, "-----", 5);
	writeline(&out, NULL, 0, crlf);

	*output_size = (uint32_t)out.pos;

	return ARMOR_SUCCESS;
}
