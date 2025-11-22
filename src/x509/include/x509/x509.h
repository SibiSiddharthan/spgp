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

typedef enum _x509_rdn_type
{
	X509_RDN_RESERVED = 0,

	X509_RDN_NAME,
	X509_RDN_SURNAME,
	X509_RDN_INITIALS,
	X509_RDN_COMMON_NAME,
	X509_RDN_GIVEN_NAME,
	X509_RDN_GENERATION_QUALIFIER,

	X509_RDN_LOCALITY_NAME,
	X509_RDN_STATE_PROVINCE_NAME,
	X509_RDN_ORGANIZATION_NAME,
	X509_RDN_ORGANIZATIONAL_UNIT_NAME,

	X509_RDN_TITLE,
	X509_RDN_PSEUDONYM,
	X509_RDN_COUNTRY_NAME,
	X509_RDN_SERIAL_NUMBER,
	X509_RDN_DN_QUALIFIER,
	X509_RDN_DOMAIN_COMPONENT,
	X509_RDN_EMAIL_ADDRESS

} x509_rdn_type;

typedef enum _x509_general_name_type
{
	X509_GN_RESERVED = 0,

	X509_GN_RFC822,
	X509_GN_DNS,
	X509_GN_X400,
	X509_GN_IP,
	X509_GN_URI,
	X509_GN_RID,

} x509_general_name_type;

typedef enum _x509_extension_type
{
	X509_EXT_RESERVED = 0,

	X509_EXT_AUTHORITY_KEY_IDENTIFIER,
	X509_EXT_SUBJECT_KEY_IDENTIFIER,
	X509_EXT_KEY_USAGE,
	X509_EXT_CERTIFICATE_POLICIES,
	X509_EXT_POLICY_MAPPINGS,
	X509_EXT_SUBJECT_ALTERNATE_NAME,
	X509_EXT_ISSUER_ALTERNATE_NAME,
	X509_EXT_SUBJECT_DIRECTORY_ATTRIBUTES,
	X509_EXT_BASIC_CONSTRAINTS,
	X509_EXT_NAME_CONSTRAINTS,
	X509_EXT_POLICY_CONSTRAINTS,
	X509_EXT_EXTENDED_KEY_USAGE,
	X509_EXT_PRIVATE_KEY_USAGE_PERIOD,
	X509_EXT_INHIBIT_ANYPOLICY,
	X509_EXT_CRL_DISTRIBUTION_POINTS,
	X509_EXT_DELTA_CRL_DISTRIBUTION_POINTS,

	X509_EXT_AUTHORITY_INFORMATION_ACCESS,
	X509_EXT_SUBJECT_INFORMATION_ACCESS,

} x509_extension_type;

typedef struct _x509_name
{
	x509_rdn_type type;
	uint16_t size;
	void *value;

	struct _x509_name *next;
} x509_name;

typedef struct _x509_rdn
{
	x509_name *name;
	struct _x509_rdn *next;
} x509_rdn;

typedef struct _x509_certificate
{
	byte_t version;
	byte_t serial_number_size;
	byte_t serial_number[20];

	uint64_t validity_start;
	uint64_t validity_end;

	byte_t signature_algorithm;

	x509_rdn *issuer;
	x509_rdn *subject;

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
