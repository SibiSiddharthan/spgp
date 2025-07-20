/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/alert.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tls_alert_read(tls_alert **alert, void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	if (size != TLS_ALERT_SIZE)
	{
		return;
	}

	*alert = malloc(sizeof(tls_alert));

	if (*alert == NULL)
	{
		return;
	}

	// 1 octet alert level
	LOAD_8(&(*alert)->level, in + pos);

	// 1 octet alert description
	LOAD_8(&(*alert)->description, in + pos);

	return;
}

uint32_t tls_alert_write(tls_alert *alert, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < TLS_ALERT_SIZE)
	{
		return 0;
	}

	// 1 octet alert level
	LOAD_8(out + pos, &alert->level);

	// 1 octet alert description
	LOAD_8(out + pos, &alert->description);

	return pos;
}
