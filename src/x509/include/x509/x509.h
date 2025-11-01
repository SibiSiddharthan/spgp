/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef X509_H
#define X509_H

#include <types.h>

typedef struct _x509_certificate
{
	byte_t version;
	byte_t serial_number[20];

	uint64_t validity_start;
	uint64_t validity_end;

	void **extensions;

} x509_certificate;

typedef struct _x509_certificate_chain
{
	x509_certificate *certificate;
	x509_certificate *parent;

} x509_certificate_chain;

#endif
