/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/handshake.h>
#include <ptr.h>

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

uint32_t tls_handshake_print(tls_handshake_header *handshake, void *buffer, uint32_t size)
{
	uint32_t pos = 0;

	// Handshake Type
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Handshake Type: ");

	switch (handshake->handshake_type)
	{
	case TLS_HELLO_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Hello Request (ID 0)\n");
		break;
	case TLS_CLIENT_HELLO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Hello (ID 1)\n");
		break;
	case TLS_SERVER_HELLO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Hello (ID 2)\n");
		break;
	case TLS_HELLO_VERIFY_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Hello Verify Request (ID 3)\n");
		break;
	case TLS_NEW_SESSION_TICKET:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "New Session Ticket (ID 4)\n");
		break;
	case TLS_END_OF_EARLY_DATA:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "End Of Early Data (ID 5)\n");
		break;
	case TLS_HELLO_RETRY_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Hello Retry Request (ID 6)\n");
		break;
	case TLS_ENCRYPTED_EXTENSIONS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Encrypted Extensions (ID 8)\n");
		break;
	case TLS_CERTIFICATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Certificate (ID 11)\n");
		break;
	case TLS_SERVER_KEY_EXCHANGE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Key Exchange (ID 12)\n");
		break;
	case TLS_CERTIFICATE_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Request (ID 13)\n");
		break;
	case TLS_SERVER_HELLO_DONE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Hello Done (ID 14)\n");
		break;
	case TLS_CERTIFICATE_VERIFY:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Verify (ID 15)\n");
		break;
	case TLS_CLIENT_KEY_EXCHANGE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Key Exchange (ID 16)\n");
		break;
	case TLS_FINISHED:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Finished (ID 20)\n");
		break;
	case TLS_CERTIFICATE_URL:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate URL (ID 21)\n");
		break;
	case TLS_CERTIFICATE_STATUS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Status (ID 22)\n");
		break;
	case TLS_SUPPLEMENTAL_DATA:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Supplemental Data (ID 23)\n");
		break;
	case TLS_KEY_UPDATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Key Update (ID 24)\n");
		break;
	case TLS_MESSAGE_HASH:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Message Hash (ID 254)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", handshake->handshake_type);
		break;
	}

	// Handshake Size
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Handshake Size: %u\n", handshake->handshake_size);

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
