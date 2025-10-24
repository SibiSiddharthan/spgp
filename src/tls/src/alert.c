/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/alert.h>
#include <tls/record.h>
#include <tls/memory.h>
#include <tls/print.h>

#include <load.h>
#include <ptr.h>

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

uint32_t tls_alert_print_body(tls_alert *alert, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;
	const char *level_name = NULL;
	const char *description_name = NULL;

	// Alert Level
	switch (alert->level)
	{
	case TLS_WARNING:
		level_name = "Warning";
		break;
	case TLS_FATAL:
		level_name = "Fatal";
		break;
	default:
		level_name = "Unknown Severity";
		break;
	}

	pos += print_format(buffer, indent, "Level: %s (ID %hhu)\n", level_name, alert->level);

	// Alert Description
	switch (alert->description)
	{
	case TLS_CLOSE_NOTIFY:
		description_name = "Close Notification";
		break;
	case TLS_UNEXPECTED_MESSAGE:
		description_name = "Unexpected Message";
		break;
	case TLS_BAD_RECORD_MAC:
		description_name = "Bad Record MAC";
		break;
	case TLS_DECRYPTION_FAILURE:
		description_name = "Decryption Failure";
		break;
	case TLS_RECORD_OVERFLOW:
		description_name = "Record Overflow";
		break;
	case TLS_DECOMPRESSION_FAILURE:
		description_name = "Decompression Failure";
		break;
	case TLS_HANDSHAKE_FAILURE:
		description_name = "Handshake Failure";
		break;
	case TLS_NO_CERTIFICATE_RESERVED:
		description_name = "No Certificate Reserved";
		break;
	case TLS_BAD_CERTIFICATE:
		description_name = "Bad Certificate";
		break;
	case TLS_UNSUPPORTED_CERTIFICATE:
		description_name = "Unsupported Certificate";
		break;
	case TLS_CERTIFICATE_REVOKED:
		description_name = "Certificate Revoked";
		break;
	case TLS_CERTIFICATE_EXPIRED:
		description_name = "Certificate Expired";
		break;
	case TLS_CERTIFICATE_UNKNOWN:
		description_name = "Certificate Unknown";
		break;
	case TLS_ILLEGAL_PARAMETER:
		description_name = "Illegal Parameter";
		break;
	case TLS_UNKNOWN_CA:
		description_name = "Unknown Certificate Authority";
		break;
	case TLS_ACCESS_DENIED:
		description_name = "Access Denied";
		break;
	case TLS_DECODE_ERROR:
		description_name = "Decode Error";
		break;
	case TLS_DECRYPT_ERROR:
		description_name = "Decrypt Error";
		break;
	case TLS_EXPORT_RESTRICTION:
		description_name = "Export Restriction";
		break;
	case TLS_PROTOCOL_VERSION:
		description_name = "Protocol Version";
		break;
	case TLS_INSUFFICIENT_SECURITY:
		description_name = "Insufficient Security";
		break;
	case TLS_INTERNAL_ERROR:
		description_name = "Internal Error";
		break;
	case TLS_INAPPROPRIATE_FALLBACK:
		description_name = "Inappropriate Fallback";
		break;
	case TLS_USER_CANCELLED:
		description_name = "User Cancelled";
		break;
	case TLS_NO_RENEGOTIATION:
		description_name = "No Renegotiation";
		break;
	case TLS_MISSING_EXTENSION:
		description_name = "Missing Extension";
		break;
	case TLS_UNSUPPORTED_EXTENSION:
		description_name = "Unsupported Extension";
		break;
	case TLS_UNRECOGNIZED_NAME:
		description_name = "Unrecognized Name";
		break;
	case TLS_BAD_CERTIFICATE_STATUS_RESPONSE:
		description_name = "Bad Certificate Status Response";
		break;
	case TLS_UNKNOWN_PSK_IDENTITY:
		description_name = "Unknown Pre-Shared Key Identity";
		break;
	case TLS_CERTIFICATE_REQUIRED:
		description_name = "Certificate Required";
		break;
	case TLS_NO_APPLICATION_PROTOCOL:
		description_name = "No Application Protocol";
		break;
	default:
		description_name = "Unknown Alert";
		break;
	}

	pos += print_format(buffer, indent, "Description: %s (ID %hhu)\n", description_name, alert->description);

	return pos;
}
