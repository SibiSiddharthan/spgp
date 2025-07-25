/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/cs.h>
#include <tls/memory.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>

tls_error_t tls_change_cipher_spec_read_body(tls_change_cipher_spec **cs, tls_record_header *header, void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	if (size != TLS_CHANGE_CIPHER_SPEC_OCTETS)
	{
		return TLS_MALFORMED_CHANGE_CIPHER_SPEC;
	}

	*cs = zmalloc(sizeof(tls_change_cipher_spec));

	if (*cs == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	(*cs)->header = *header;

	// 1 octet state
	LOAD_8(&(*cs)->state, in + pos);
	pos += 1;

	return TLS_SUCCESS;
}

uint32_t tls_change_cipher_spec_write_body(tls_change_cipher_spec *cs, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < TLS_CHANGE_CIPHER_SPEC_OCTETS)
	{
		return 0;
	}

	LOAD_8(out + pos, &cs->state);
	pos += 1;

	return pos;
}

uint32_t tls_change_cipher_spec_print(tls_change_cipher_spec *cs, void *buffer, uint32_t size, uint32_t indent)
{
	// State
	if (cs->state == TLS_CHANGE_CIPHER_SPEC_TYPE)
	{
		return snprintf(buffer, size, "%*sChange Cipher Spec: Yes (1)", indent * 4, "");
	}
	else
	{
		return snprintf(buffer, size, "%*sChange Cipher Spec: Unknown (%hhu)", indent * 4, "", cs->state);
	}
}
