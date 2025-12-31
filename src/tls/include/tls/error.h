/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_ERROR_H
#define TLS_ERROR_H

#include <tls/types.h>

typedef enum _tls_error_t
{
	// No error
	TLS_SUCCESS = 0,

	// General errors
	TLS_NO_MEMORY,
	TLS_INSUFFICIENT_DATA,
	TLS_BUFFER_TOO_SMALL,
	TLS_INVALID_PARAMETER,

	// Version errors
	TLS_UNKNOWN_PROTOCOL_VERSION,
	TLS_MALFORMED_ALERT,
	TLS_MALFORMED_CHANGE_CIPHER_SPEC,

	// Extension errors
	TLS_MALFORMED_EXTENSION_SIZE,
	TLS_INVALID_RECORD_LIMIT,

} tls_error_t;

#endif
