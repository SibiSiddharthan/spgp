/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <print.h>
#include <buffer.h>

uint32_t vxprint(buffer_t *buffer, const char *format, va_list args)
{
	uint32_t result = 0;
	byte_t byte = 0;

	while ((byte = *format++) != '\0')
	{
		if (byte == '%')
		{
			byte = *format++;

			if (byte == '\0')
			{
				break;
			}

			if (byte == '%')
			{
				result += writebyte(buffer, '%');
				continue;
			}

			continue;
		}

		result += writebyte(buffer, byte);
	}

	return result;
}
