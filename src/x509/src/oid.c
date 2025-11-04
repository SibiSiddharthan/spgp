/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <x509/oid.h>
#include <string.h>

// Refer RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
// Refer RFC 5758: Internet X.509 Public Key Infrastructure: Additional Algorithms and Identifiers for DSA and ECDSA
// Refer RFC 8692: Internet X.509 Public Key Infrastructure: Additional Algorithm Identifiers for RSASSA-PSS and ECDSA Using SHAKEs

// Refer NIST Computer Security Objects Register

const byte_t x509_dsa_sha1_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03};
const byte_t x509_dsa_sha224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01};
const byte_t x509_dsa_sha256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02};
const byte_t x509_dsa_sha384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03};
const byte_t x509_dsa_sha512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04};
const byte_t x509_dsa_sha3_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x05};
const byte_t x509_dsa_sha3_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x06};
const byte_t x509_dsa_sha3_384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x07};
const byte_t x509_dsa_sha3_512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x08};

const byte_t x509_ecdsa_sha1_oid[] = {0x01, 0x02, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01};
const byte_t x509_ecdsa_sha224_oid[] = {0x01, 0x02, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01};
const byte_t x509_ecdsa_sha256_oid[] = {0x01, 0x02, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
const byte_t x509_ecdsa_sha384_oid[] = {0x01, 0x02, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
const byte_t x509_ecdsa_sha512_oid[] = {0x01, 0x02, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};
const byte_t x509_ecdsa_sha3_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09};
const byte_t x509_ecdsa_sha3_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0A};
const byte_t x509_ecdsa_sha3_384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0B};
const byte_t x509_ecdsa_sha3_512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0C};
const byte_t x509_ecdsa_shake128_oid[] = {0x01, 0x03, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x20};
const byte_t x509_ecdsa_shake256_oid[] = {0x01, 0x03, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x21};

x509_signature_algorithm x509_signature_oid_decode(byte_t *oid, uint32_t size)
{
	if (size == 7)
	{
		if (memcmp(oid, x509_dsa_sha1_oid, 7) == 0)
		{
			return X509_DSA_SHA1;
		}
	}

	if (size == 8)
	{
		if (memcmp(oid, x509_ecdsa_sha1_oid, 8) == 0)
		{
			return X509_ECDSA_SHA1;
		}
	}

	if (size == 9)
	{
		// Common Prefix
		if (memcmp(oid, x509_dsa_sha224_oid, 8) == 0)
		{
			switch (oid[8])
			{
			case 0x1:
				return X509_DSA_SHA224;
			case 0x2:
				return X509_DSA_SHA256;
			case 0x3:
				return X509_DSA_SHA384;
			case 0x4:
				return X509_DSA_SHA512;
			case 0x5:
				return X509_DSA_SHA3_224;
			case 0x6:
				return X509_DSA_SHA3_256;
			case 0x7:
				return X509_DSA_SHA3_384;
			case 0x8:
				return X509_DSA_SHA3_512;
			case 0x9:
				return X509_ECDSA_SHA3_224;
			case 0xA:
				return X509_ECDSA_SHA3_256;
			case 0xB:
				return X509_ECDSA_SHA3_384;
			case 0xc:
				return X509_ECDSA_SHA3_512;
			}
		}

		// Common Prefix
		if (memcmp(oid, x509_ecdsa_sha224_oid, 8) == 0)
		{
			switch (oid[8])
			{
			case 0x1:
				return X509_ECDSA_SHA224;
			case 0x2:
				return X509_ECDSA_SHA256;
			case 0x3:
				return X509_ECDSA_SHA384;
			case 0x4:
				return X509_ECDSA_SHA512;
			}
		}

		// Common Prefix
		if (memcmp(oid, x509_ecdsa_sha224_oid, 8) == 0)
		{
			switch (oid[8])
			{
			case 0x1:
				return X509_ECDSA_SHA224;
			case 0x2:
				return X509_ECDSA_SHA256;
			case 0x3:
				return X509_ECDSA_SHA384;
			case 0x4:
				return X509_ECDSA_SHA512;
			}
		}
	}

	return X509_SIG_RESERVED;
}
