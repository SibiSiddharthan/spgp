/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/handshake.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tls_handshake_read(void **handshake, void *data, uint32_t size)
{
	void *result = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	tls_handshake_header header = {0};

	// 1-octet handshake type
	header.handshake_type = in[pos];
	pos += 1;

	// 3-octet handshake size
	header.handshake_size = (in[pos] << 16) + (in[pos + 1] << 8) + in[pos + 2];
	pos += 3;

	result = malloc(sizeof(tls_handshake_header));

	if (result == NULL)
	{
		return;
	}

	memset(result, 0, sizeof(tls_handshake_header));
	memcpy(result, &header, sizeof(tls_handshake_header));

	switch (header.handshake_type)
	{
	case TLS_HELLO_REQUEST:
	case TLS_CLIENT_HELLO:
	case TLS_SERVER_HELLO:
	case TLS_HELLO_VERIFY_REQUEST:
	case TLS_NEW_SESSION_TICKET:
	case TLS_END_OF_EARLY_DATA:
	case TLS_HELLO_RETRY_REQUEST:
	case TLS_ENCRYPTED_EXTENSIONS:
	case TLS_CERTIFICATE:
	case TLS_SERVER_KEY_EXCHANGE:
	case TLS_CERTIFICATE_REQUEST:
	case TLS_SERVER_HELLO_DONE:
	case TLS_CERTIFICATE_VERIFY:
	case TLS_CLIENT_KEY_EXCHANGE:
	case TLS_FINISHED:
	case TLS_CERTIFICATE_URL:
	case TLS_CERTIFICATE_STATUS:
	case TLS_SUPPLEMENTAL_DATA:
	case TLS_KEY_UPDATE:
	case TLS_MESSAGE_HASH:
		break;
	}

	*handshake = result;
}

uint32_t tls_handshake_write(tls_handshake_header *handshake, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < (4 + handshake->handshake_size))
	{
		return 0;
	}

	// 1-octet handshake type
	out[pos++] = handshake->handshake_type;

	// 3-octet handshake size
	out[pos++] = (handshake->handshake_size >> 16) & 0xFF;
	out[pos++] = (handshake->handshake_size >> 8) & 0xFF;
	out[pos++] = (handshake->handshake_size >> 0) & 0xFF;

	switch (handshake->handshake_type)
	{
	case TLS_HELLO_REQUEST:
	case TLS_CLIENT_HELLO:
	case TLS_SERVER_HELLO:
	case TLS_HELLO_VERIFY_REQUEST:
	case TLS_NEW_SESSION_TICKET:
	case TLS_END_OF_EARLY_DATA:
	case TLS_HELLO_RETRY_REQUEST:
	case TLS_ENCRYPTED_EXTENSIONS:
	case TLS_CERTIFICATE:
	case TLS_SERVER_KEY_EXCHANGE:
	case TLS_CERTIFICATE_REQUEST:
	case TLS_SERVER_HELLO_DONE:
	case TLS_CERTIFICATE_VERIFY:
	case TLS_CLIENT_KEY_EXCHANGE:
	case TLS_FINISHED:
	case TLS_CERTIFICATE_URL:
	case TLS_CERTIFICATE_STATUS:
	case TLS_SUPPLEMENTAL_DATA:
	case TLS_KEY_UPDATE:
	case TLS_MESSAGE_HASH:
		break;
	}

	return pos;
}
