/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/alert.h>
#include <tls/record.h>
#include <tls/memory.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

tls_error_t tls_alert_read_body(tls_alert **alert, tls_record_header *header, void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	if (size != TLS_ALERT_OCTETS)
	{
		return TLS_MALFORMED_ALERT;
	}

	*alert = zmalloc(sizeof(tls_alert));

	if (*alert == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	(*alert)->header = *header;

	// 1 octet alert level
	LOAD_8(&(*alert)->level, in + pos);
	pos += 1;

	// 1 octet alert description
	LOAD_8(&(*alert)->description, in + pos);
	pos += 1;

	return TLS_SUCCESS;
}

uint32_t tls_alert_write_body(tls_alert *alert, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < TLS_ALERT_OCTETS)
	{
		return 0;
	}

	// 1 octet alert level
	LOAD_8(out + pos, &alert->level);
	pos += 1;

	// 1 octet alert description
	LOAD_8(out + pos, &alert->description);
	pos += 1;

	return pos;
}

uint32_t tls_alert_print(tls_alert *alert, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	// Alert Level
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sAlert Level: ", indent * 4, "");

	switch (alert->level)
	{
	case TLS_WARNING:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Warning (ID 1)\n");
		break;
	case TLS_FATAL:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Fatal (ID 2)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", alert->level);
		break;
	}

	// Alert Description
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sAlert Description: ", indent * 4, "");

	switch (alert->description)
	{
	case TLS_CLOSE_NOTIFY:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Close Notification (ID 0)\n");
		break;
	case TLS_UNEXPECTED_MESSAGE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unexpected Message (ID 10)\n");
		break;
	case TLS_BAD_RECORD_MAC:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Bad Record MAC (ID 20)\n");
		break;
	case TLS_DECRYPTION_FAILURE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Decryption Failure (ID 21)\n");
		break;
	case TLS_RECORD_OVERFLOW:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Record Overflow (ID 22)\n");
		break;
	case TLS_DECOMPRESSION_FAILURE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Decompression Failure (ID 30)\n");
		break;
	case TLS_HANDSHAKE_FAILURE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Handshake Failure (ID 40)\n");
		break;
	case TLS_NO_CERTIFICATE_RESERVED:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "No Certificate Reserved (ID 41)\n");
		break;
	case TLS_BAD_CERTIFICATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Bad Certificate (ID 42)\n");
		break;
	case TLS_UNSUPPORTED_CERTIFICATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unsupported Certificate (ID 43)\n");
		break;
	case TLS_CERTIFICATE_REVOKED:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Revoked (ID 44)\n");
		break;
	case TLS_CERTIFICATE_EXPIRED:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Expired (ID 45)\n");
		break;
	case TLS_CERTIFICATE_UNKNOWN:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Unknown (ID 46)\n");
		break;
	case TLS_ILLEGAL_PARAMETER:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Illegal Parameter (ID 47)\n");
		break;
	case TLS_UNKNOWN_CA:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown Certificate Authority (ID 48)\n");
		break;
	case TLS_ACCESS_DENIED:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Access Denied (ID 49)\n");
		break;
	case TLS_DECODE_ERROR:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Decode Error (ID 50)\n");
		break;
	case TLS_DECRYPT_ERROR:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Decrypt Error (ID 51)\n");
		break;
	case TLS_EXPORT_RESTRICTION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Export Restriction (ID 60)\n");
		break;
	case TLS_PROTOCOL_VERSION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Protocol Version (ID 70)\n");
		break;
	case TLS_INSUFFICIENT_SECURITY:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Insufficient Security (ID 71)\n");
		break;
	case TLS_INTERNAL_ERROR:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Internal Error (ID 80)\n");
		break;
	case TLS_INAPPROPRIATE_FALLBACK:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Inappropriate Fallback (ID 86)\n");
		break;
	case TLS_USER_CANCELLED:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "User Cancelled (ID 90)\n");
		break;
	case TLS_NO_RENEGOTIATION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "No Renegotiation (ID 100)\n");
		break;
	case TLS_MISSING_EXTENSION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Missing Extension (ID 109)\n");
		break;
	case TLS_UNSUPPORTED_EXTENSION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unsupported Extension (ID 110)\n");
		break;
	case TLS_UNRECOGNIZED_NAME:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unrecognized Name (ID 112)\n");
		break;
	case TLS_BAD_CERTIFICATE_STATUS_RESPONSE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Bad Certificate Status Response (ID 113)\n");
		break;
	case TLS_UNKNOWN_PSK_IDENTITY:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown Pre-Shared Key Identity (ID 115)\n");
		break;
	case TLS_CERTIFICATE_REQUIRED:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Required (ID 116)\n");
		break;
	case TLS_NO_APPLICATION_PROTOCOL:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "No Application Protocol (ID 120)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", alert->description);
		break;
	}

	return pos;
}
