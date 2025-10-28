/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef ASN1_TAG_H
#define ASN1_TAG_H

typedef enum _asn1_type
{
	ASN1_INTEGER = 0x02,
	ASN1_BIT_STRING = 0x03,
	ASN1_OCTET_STRING = 0x04,
	ASN1_NULL = 0x05,
	ASN1_OBJECT_IDENTIFIER = 0x06,
	ASN1_UTF8_STRING = 0x0C,
	ASN1_PRINTABLE_STRING = 0x13,
	ASN1_IA5_STRING = 0x16,
	ASN1_UTC_TIME = 0x17,
	ASN1_GENERAL_TIME = 0x17,
	ASN1_SEQUENCE = 0x30,
	ASN1_SET = 0x31

} asn1_type;

#endif
