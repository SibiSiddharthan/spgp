/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef X509_OID_H
#define X509_OID_H

#include <x509/algorithm.h>
#include <x509/error.h>
#include <x509/x509.h>

uint32_t x509_algorithm_oid_size(x509_algorithm algorithm);
uint32_t x509_algorithm_encode(x509_algorithm algorithm, void *buffer, uint32_t size);
x509_algorithm x509_algorithm_oid_decode(byte_t *oid, uint32_t size);

uint32_t x509_hash_oid_size(x509_hash_algorithm algorithm);
uint32_t x509_hash_oid_encode(x509_hash_algorithm algorithm, void *buffer, uint32_t size);
x509_hash_algorithm x509_hash_oid_decode(byte_t *oid, uint32_t size);

uint32_t x509_signature_oid_size(x509_signature_algorithm algorithm);
uint32_t x509_signature_oid_encode(x509_signature_algorithm algorithm, void *buffer, uint32_t size);
x509_signature_algorithm x509_signature_oid_decode(byte_t *oid, uint32_t size);

uint32_t x509_curve_oid_size(x509_curve_id id);
x509_curve_id x509_curve_oid_encode(x509_curve_id id, void *buffer, uint32_t size);
x509_curve_id x509_curve_oid_decode(byte_t *oid, uint32_t size);

x509_rdn_type x509_rdn_oid_decode(byte_t *oid, uint32_t size);

x509_extension_type x509_extension_oid_decode(byte_t *oid, uint32_t size);

uint32_t oid_encode(void *buffer, uint32_t buffer_size, void *oid, uint32_t oid_size);
uint32_t oid_decode(void *oid, uint32_t oid_size, void *buffer, uint32_t buffer_size);

#endif
