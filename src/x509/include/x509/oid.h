/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef X509_OID_H
#define X509_OID_H

#include <x509/algorithm.h>
#include <x509/error.h>

x509_signature_algorithm x509_signature_oid_decode(byte_t *oid, uint32_t size);

#endif
