/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/extensions.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tls_extension_read(void **extension, void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	tls_extension_type extension_type = 0;
	uint16_t extension_size = 0;

	// 2 octet extension type
	LOAD_16BE(&extension_type, in + pos);
	pos += 2;

	// 2 octet extension size
	LOAD_16BE(&extension_size, in + pos);
	pos += 2;

	return;
}

uint32_t tls_extension_write(void *extension, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	tls_extension_header *header = extension;

	// 2 octet extension type
	LOAD_16BE(out + pos, &header->extension);
	pos += 2;

	// 2 octet extension size
	LOAD_16BE(out + pos, &header->size);
	pos += 2;

	return pos;
}

uint32_t tls_extension_print(void *extension, void *buffer, uint32_t size)
{
	uint32_t pos = 0;

	tls_extension_header *header = extension;

	// Extension Type
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Extension Type: ");

	// Extension Size
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Extension Size: %hu bytes", header->size);

	return pos;
}
