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

void tls_change_cipher_spec_read(void **cs, void *data, uint32_t size)
{
	tls_change_cipher_spec *ccs = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	ccs = zmalloc(sizeof(tls_change_cipher_spec));

	if (ccs == NULL)
	{
		return;
	}

	// 1 octet state
	LOAD_8(&ccs->state, in + pos);
	pos += 1;

	*cs = ccs;
}

uint32_t tls_change_cipher_spec_write(tls_change_cipher_spec *cs, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

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
