/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef X509_H
#define X509_H

#include <x509/error.h>

typedef enum _x509_certificate_version
{
	X509_CERTIFICATE_V1 = 0,
	X509_CERTIFICATE_V2 = 1,
	X509_CERTIFICATE_V3 = 2
} x509_certificate_version;

typedef struct _x509_certificate
{
	byte_t version;
	byte_t serial_number_size;
	byte_t serial_number[20];

	uint64_t validity_start;
	uint64_t validity_end;

	byte_t signature_algorithm;

	void **extensions;

} x509_certificate;

typedef struct _x509_certificate_chain
{
	uint32_t count;
	uint32_t capacity;

	x509_certificate **certificates;

} x509_certificate_chain;

x509_error_t x509_certificate_read(x509_certificate **certificate, void *data, size_t *size);
size_t x509_certificate_write(x509_certificate *certificate, uint32_t options, void *buffer, size_t size);

x509_error_t x509_certificate_chain_read(x509_certificate **certificate, void *data, size_t *size);
size_t x509_certificate_chain_write(x509_certificate **certificate, uint32_t options, void *data, size_t size);

#endif
