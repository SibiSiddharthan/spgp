/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_CIPHER_SPEC_H
#define TLS_CIPHER_SPEC_H

#include <tls/error.h>
#include <tls/record.h>

#define TLS_CHANGE_CIPHER_SPEC_OCTETS 1
#define TLS_CHANGE_CIPHER_SPEC_TYPE   1

typedef struct _tls_change_cipher_spec
{
	tls_record_header header;
	uint8_t state;
} tls_change_cipher_spec;

tls_error_t tls_change_cipher_spec_read_body(tls_change_cipher_spec **cs, tls_record_header *header, void *data, uint32_t size);
uint32_t tls_change_cipher_spec_write_body(tls_change_cipher_spec *cs, void *buffer, uint32_t size);
uint32_t tls_change_cipher_spec_print(tls_change_cipher_spec *cs, void *buffer, uint32_t size, uint32_t indent);

#endif
