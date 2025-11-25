/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <x509/oid.h>
#include <string.h>

#include <minmax.h>

// clang-format off

// Refer RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
// Refer RFC 4055: Additional Algorithms and Identifiers for RSA Cryptography for use in the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
// Refer RFC 5758: Internet X.509 Public Key Infrastructure: Additional Algorithms and Identifiers for DSA and ECDSA 
// Refer RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2
// Refer RFC 8410: Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 for Use in the Internet X.509 Public Key Infrastructure
// Refer RFC 8692: Internet X.509 Public Key Infrastructure: Additional Algorithm Identifiers for RSASSA-PSS and ECDSA Using SHAKEs

// clang-format on

// Refer NIST Computer Security Objects Register

const byte_t x509_dsa_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01};

const byte_t x509_ecdsa_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
const byte_t x509_ecdh_oid[] = {0x2B, 0x81, 0x04, 0x01, 0x0C};
const byte_t x509_ecmqv_oid[] = {0x2B, 0x81, 0x04, 0x01, 0x0D};

const byte_t x509_rsa_pkcs_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
const byte_t x509_rsa_oaep_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07};
const byte_t x509_rsa_pss_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A};

const byte_t x509_x25519_oid[] = {0x2B, 0x65, 0x6E};
const byte_t x509_x448_oid[] = {0x2B, 0x65, 0x6F};
const byte_t x509_ed25519_oid[] = {0x2B, 0x65, 0x70};
const byte_t x509_ed448_oid[] = {0x2B, 0x65, 0x71};

uint32_t x509_algorithm_oid_size(x509_algorithm algorithm)
{
	switch (algorithm)
	{
	case X509_RESERVED:
		return 0;

	case X509_DSA:
	case X509_ECDSA:
		return 7;

	case X509_ECDH:
	case X509_ECMQV:
		return 5;

	case X509_RSA_PKCS:
	case X509_RSA_OAEP:
	case X509_RSA_PSS:
		return 9;

	case X509_X25519:
	case X509_X448:
	case X509_ED25519:
	case X509_ED448:
		return 3;
	}

	return 0;
}

uint32_t x509_algorithm_encode(x509_algorithm algorithm, void *buffer, uint32_t size)
{
	uint32_t required_size = 0;

	required_size = x509_algorithm_oid_size(algorithm);

	if (size < required_size)
	{
		return 0;
	}

	if (required_size == 0)
	{
		return 0;
	}

	switch (algorithm)
	{
	case X509_RESERVED:
		break;

	case X509_DSA:
		memcpy(buffer, x509_dsa_oid, required_size);
		break;
	case X509_ECDSA:
		memcpy(buffer, x509_ecdsa_oid, required_size);
		break;

	case X509_ECDH:
		memcpy(buffer, x509_ecdh_oid, required_size);
		break;
	case X509_ECMQV:
		memcpy(buffer, x509_ecmqv_oid, required_size);
		break;

	case X509_RSA_PKCS:
		memcpy(buffer, x509_rsa_pkcs_oid, required_size);
		break;
	case X509_RSA_OAEP:
		memcpy(buffer, x509_rsa_oaep_oid, required_size);
		break;
	case X509_RSA_PSS:
		memcpy(buffer, x509_rsa_pss_oid, required_size);
		break;

	case X509_X25519:
		memcpy(buffer, x509_x25519_oid, required_size);
		break;
	case X509_X448:
		memcpy(buffer, x509_x448_oid, required_size);
		break;
	case X509_ED25519:
		memcpy(buffer, x509_ed25519_oid, required_size);
		break;
	case X509_ED448:
		memcpy(buffer, x509_ed448_oid, required_size);
		break;
	}

	return required_size;
}

x509_algorithm x509_algorithm_oid_decode(byte_t *oid, uint32_t size)
{
	if (size == 0)
	{
		return X509_RESERVED;
	}

	if (oid[0] == 0x2A)
	{
		if (size == 7)
		{
			if (oid[1] == 0x86 && oid[2] == 0x48 && oid[3] == 0xCE)
			{
				if (oid[4] == 0x38 && oid[5] == 0x04 && oid[6] == 0x01)
				{
					return X509_DSA;
				}

				if (oid[4] == 0x3D && oid[5] == 0x02 && oid[6] == 0x01)
				{
					return X509_ECDSA;
				}
			}
		}

		if (size == 9)
		{
			if (memcmp(oid + 1, x509_rsa_pkcs_oid + 1, 7) == 0)
			{
				switch (oid[8])
				{
				case 0x01:
					return X509_RSA_PKCS;
				case 0x07:
					return X509_RSA_OAEP;
				case 0x0A:
					return X509_RSA_PSS;
				}
			}
		}
	}

	if (oid[0] == 0x2B)
	{
		if (size == 3)
		{
			if (oid[1] == 0x65)
			{
				switch (oid[2])
				{
				case 0x6E:
					return X509_X25519;
				case 0x6F:
					return X509_X448;
				case 0x70:
					return X509_ED25519;
				case 0x71:
					return X509_ED448;
				}
			}
		}

		if (size == 5)
		{
			if (oid[1] == 0x81 && oid[2] == 0x04 && oid[3] == 0x01)
			{
				if (oid[4] == 0x0C)
				{
					return X509_ECDH;
				}

				if (oid[5] == 0x0D)
				{
					return X509_ECMQV;
				}
			}
		}
	}

	return X509_RESERVED;
}

const byte_t x509_hash_md5_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05};
const byte_t x509_hash_sha1_oid[] = {0x2B, 0x0E, 0x03, 0x02, 0x1A};
const byte_t x509_hash_sha224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
const byte_t x509_hash_sha256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
const byte_t x509_hash_sha384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
const byte_t x509_hash_sha512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04};
const byte_t x509_hash_sha512_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05};
const byte_t x509_hash_sha512_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06};
const byte_t x509_hash_sha3_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07};
const byte_t x509_hash_sha3_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08};
const byte_t x509_hash_sha3_384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09};
const byte_t x509_hash_sha3_512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A};
const byte_t x509_hash_shake128_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B};
const byte_t x509_hash_shake256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C};
const byte_t x509_hash_shake128x_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x11};
const byte_t x509_hash_shake256x_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x12};

uint32_t x509_hash_oid_size(x509_hash_algorithm algorithm)
{
	switch (algorithm)
	{
	case X509_HASH_RESERVED:
		return 0;

	case X509_HASH_MD5:
		return 8;
	case X509_HASH_SHA1:
		return 5;

	case X509_HASH_SHA224:
	case X509_HASH_SHA256:
	case X509_HASH_SHA384:
	case X509_HASH_SHA512:
	case X509_HASH_SHA512_224:
	case X509_HASH_SHA512_256:
	case X509_HASH_SHA3_224:
	case X509_HASH_SHA3_256:
	case X509_HASH_SHA3_384:
	case X509_HASH_SHA3_512:
	case X509_HASH_SHAKE128:
	case X509_HASH_SHAKE256:
	case X509_HASH_SHAKE128X:
	case X509_HASH_SHAKE256X:
		return 9;
	}

	return 0;
}

uint32_t x509_hash_oid_encode(x509_hash_algorithm algorithm, void *buffer, uint32_t size)
{
	uint32_t required_size = 0;

	required_size = x509_hash_oid_size(algorithm);

	if (size < required_size)
	{
		return 0;
	}

	if (required_size == 0)
	{
		return 0;
	}

	switch (algorithm)
	{
	case X509_HASH_RESERVED:
		return 0;

	case X509_HASH_MD5:
		memcpy(buffer, x509_hash_md5_oid, required_size);
		break;
	case X509_HASH_SHA1:
		memcpy(buffer, x509_hash_sha1_oid, required_size);
		break;

	case X509_HASH_SHA224:
		memcpy(buffer, x509_hash_sha224_oid, required_size);
		break;
	case X509_HASH_SHA256:
		memcpy(buffer, x509_hash_sha256_oid, required_size);
		break;
	case X509_HASH_SHA384:
		memcpy(buffer, x509_hash_sha384_oid, required_size);
		break;
	case X509_HASH_SHA512:
		memcpy(buffer, x509_hash_sha512_oid, required_size);
		break;
	case X509_HASH_SHA512_224:
		memcpy(buffer, x509_hash_sha512_224_oid, required_size);
		break;
	case X509_HASH_SHA512_256:
		memcpy(buffer, x509_hash_sha512_256_oid, required_size);
		break;
	case X509_HASH_SHA3_224:
		memcpy(buffer, x509_hash_sha3_224_oid, required_size);
		break;
	case X509_HASH_SHA3_256:
		memcpy(buffer, x509_hash_sha3_256_oid, required_size);
		break;
	case X509_HASH_SHA3_384:
		memcpy(buffer, x509_hash_sha3_384_oid, required_size);
		break;
	case X509_HASH_SHA3_512:
		memcpy(buffer, x509_hash_sha3_512_oid, required_size);
		break;
	case X509_HASH_SHAKE128:
		memcpy(buffer, x509_hash_shake128_oid, required_size);
		break;
	case X509_HASH_SHAKE256:
		memcpy(buffer, x509_hash_shake256_oid, required_size);
		break;
	case X509_HASH_SHAKE128X:
		memcpy(buffer, x509_hash_shake128x_oid, required_size);
		break;
	case X509_HASH_SHAKE256X:
		memcpy(buffer, x509_hash_shake256x_oid, required_size);
		break;
	}

	return required_size;
}

x509_hash_algorithm x509_hash_oid_decode(byte_t *oid, uint32_t size)
{
	if (size == 5)
	{
		if (memcmp(oid, x509_hash_sha1_oid, 5) == 0)
		{
			return X509_HASH_SHA1;
		}
	}

	if (size == 8)
	{
		if (memcmp(oid, x509_hash_md5_oid, 9) == 0)
		{
			return X509_HASH_MD5;
		}
	}

	if (size == 9)
	{
		if (memcmp(oid, x509_hash_sha224_oid, 8) == 0)
		{
			switch (oid[8])
			{
			case 0x01:
				return X509_HASH_SHA224;
			case 0x02:
				return X509_HASH_SHA256;
			case 0x03:
				return X509_HASH_SHA384;
			case 0x04:
				return X509_HASH_SHA512;
			case 0x05:
				return X509_HASH_SHA512_224;
			case 0x06:
				return X509_HASH_SHA512_256;
			case 0x07:
				return X509_HASH_SHA3_224;
			case 0x08:
				return X509_HASH_SHA3_256;
			case 0x09:
				return X509_HASH_SHA3_384;
			case 0x0A:
				return X509_HASH_SHA3_512;
			case 0x0B:
				return X509_HASH_SHAKE128;
			case 0x0C:
				return X509_HASH_SHAKE256;
			case 0x11:
				return X509_HASH_SHAKE128X;
			case 0x12:
				return X509_HASH_SHAKE256X;
			}
		}
	}

	return X509_HASH_RESERVED;
}

const byte_t x509_sig_rsa_pkcs_md5_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04};
const byte_t x509_sig_rsa_pkcs_sha1_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05};
const byte_t x509_sig_rsa_pkcs_sha256_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
const byte_t x509_sig_rsa_pkcs_sha384_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};
const byte_t x509_sig_rsa_pkcs_sha512_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D};
const byte_t x509_sig_rsa_pkcs_sha224_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0E};
const byte_t x509_sig_rsa_pkcs_sha3_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0D};
const byte_t x509_sig_rsa_pkcs_sha3_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0E};
const byte_t x509_sig_rsa_pkcs_sha3_384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0F};
const byte_t x509_sig_rsa_pkcs_sha3_512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10};

const byte_t x509_sig_rsa_pss_shake128_oid[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1E};
const byte_t x509_sig_rsa_pss_shake256_oid[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1F};

const byte_t x509_sig_dsa_sha1_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03};
const byte_t x509_sig_dsa_sha224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01};
const byte_t x509_sig_dsa_sha256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02};
const byte_t x509_sig_dsa_sha384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03};
const byte_t x509_sig_dsa_sha512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04};
const byte_t x509_sig_dsa_sha3_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x05};
const byte_t x509_sig_dsa_sha3_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x06};
const byte_t x509_sig_dsa_sha3_384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x07};
const byte_t x509_sig_dsa_sha3_512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x08};

const byte_t x509_sig_ecdsa_sha1_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01};
const byte_t x509_sig_ecdsa_sha224_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01};
const byte_t x509_sig_ecdsa_sha256_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
const byte_t x509_sig_ecdsa_sha384_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
const byte_t x509_sig_ecdsa_sha512_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};
const byte_t x509_sig_ecdsa_sha3_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09};
const byte_t x509_sig_ecdsa_sha3_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0A};
const byte_t x509_sig_ecdsa_sha3_384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0B};
const byte_t x509_sig_ecdsa_sha3_512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0C};
const byte_t x509_sig_ecdsa_shake128_oid[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x20};
const byte_t x509_sig_ecdsa_shake256_oid[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x21};

const byte_t x509_sig_mldsa_44_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};
const byte_t x509_sig_mldsa_65_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
const byte_t x509_sig_mldsa_87_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};
const byte_t x509_sig_hash_mldsa_44_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x20};
const byte_t x509_sig_hash_mldsa_65_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x21};
const byte_t x509_sig_hash_mldsa_87_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x22};

uint32_t x509_signature_oid_size(x509_signature_algorithm algorithm)
{
	switch (algorithm)
	{
	case X509_SIG_RESERVED:
		return 0;

	// RSA
	case X509_SIG_RSA_PSS:
	case X509_SIG_RSA_PKCS_MD5:
	case X509_SIG_RSA_PKCS_SHA1:
	case X509_SIG_RSA_PKCS_SHA224:
	case X509_SIG_RSA_PKCS_SHA256:
	case X509_SIG_RSA_PKCS_SHA384:
	case X509_SIG_RSA_PKCS_SHA512:
	case X509_SIG_RSA_PKCS_SHA3_224:
	case X509_SIG_RSA_PKCS_SHA3_256:
	case X509_SIG_RSA_PKCS_SHA3_384:
	case X509_SIG_RSA_PKCS_SHA3_512:
		return 9;

	// DSA
	case X509_SIG_DSA_SHA224:
	case X509_SIG_DSA_SHA256:
	case X509_SIG_DSA_SHA384:
	case X509_SIG_DSA_SHA512:
	case X509_SIG_DSA_SHA3_224:
	case X509_SIG_DSA_SHA3_256:
	case X509_SIG_DSA_SHA3_384:
	case X509_SIG_DSA_SHA3_512:
		return 9;

	// ECDSA
	case X509_SIG_ECDSA_SHA224:
	case X509_SIG_ECDSA_SHA256:
	case X509_SIG_ECDSA_SHA384:
	case X509_SIG_ECDSA_SHA512:
	case X509_SIG_ECDSA_SHA3_224:
	case X509_SIG_ECDSA_SHA3_256:
	case X509_SIG_ECDSA_SHA3_384:
	case X509_SIG_ECDSA_SHA3_512:
		return 9;

	case X509_SIG_DSA_SHA1:
	case X509_SIG_ECDSA_SHA1:
		return 7;

	case X509_SIG_RSA_PSS_SHAKE128:
	case X509_SIG_RSA_PSS_SHAKE256:
	case X509_SIG_ECDSA_SHAKE128:
	case X509_SIG_ECDSA_SHAKE256:
		return 8;

	case X509_SIG_ED25519:
	case X509_SIG_ED448:
		return 3;

	// MLDSA
	case X509_SIG_MLDSA_44:
	case X509_SIG_MLDSA_65:
	case X509_SIG_MLDSA_87:
	case X509_SIG_HASH_MLDSA_44:
	case X509_SIG_HASH_MLDSA_65:
	case X509_SIG_HASH_MLDSA_87:
		return 9;
	}

	return 0;
}

uint32_t x509_signature_oid_encode(x509_signature_algorithm algorithm, void *buffer, uint32_t size)
{
	uint32_t required_size = 0;

	required_size = x509_signature_oid_size(algorithm);

	if (size < required_size)
	{
		return 0;
	}

	if (required_size == 0)
	{
		return 0;
	}

	switch (algorithm)
	{
	case X509_SIG_RESERVED:
		return 0;

	// RSA
	case X509_SIG_RSA_PSS:
		memcpy(buffer, x509_rsa_pss_oid, required_size);
		break;
	case X509_SIG_RSA_PSS_SHAKE128:
		memcpy(buffer, x509_sig_rsa_pss_shake128_oid, required_size);
		break;
	case X509_SIG_RSA_PSS_SHAKE256:
		memcpy(buffer, x509_sig_rsa_pss_shake256_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_MD5:
		memcpy(buffer, x509_sig_rsa_pkcs_md5_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_SHA1:
		memcpy(buffer, x509_sig_rsa_pkcs_sha1_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_SHA224:
		memcpy(buffer, x509_sig_rsa_pkcs_sha224_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_SHA256:
		memcpy(buffer, x509_sig_rsa_pkcs_sha256_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_SHA384:
		memcpy(buffer, x509_sig_rsa_pkcs_sha384_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_SHA512:
		memcpy(buffer, x509_sig_rsa_pkcs_sha512_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_SHA3_224:
		memcpy(buffer, x509_sig_rsa_pkcs_sha3_224_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_SHA3_256:
		memcpy(buffer, x509_sig_rsa_pkcs_sha3_256_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_SHA3_384:
		memcpy(buffer, x509_sig_rsa_pkcs_sha3_384_oid, required_size);
		break;
	case X509_SIG_RSA_PKCS_SHA3_512:
		memcpy(buffer, x509_sig_rsa_pkcs_sha3_512_oid, required_size);
		break;

	// DSA
	case X509_SIG_DSA_SHA1:
		memcpy(buffer, x509_sig_dsa_sha1_oid, required_size);
		break;
	case X509_SIG_DSA_SHA224:
		memcpy(buffer, x509_sig_dsa_sha224_oid, required_size);
		break;
	case X509_SIG_DSA_SHA256:
		memcpy(buffer, x509_sig_dsa_sha256_oid, required_size);
		break;
	case X509_SIG_DSA_SHA384:
		memcpy(buffer, x509_sig_dsa_sha384_oid, required_size);
		break;
	case X509_SIG_DSA_SHA512:
		memcpy(buffer, x509_sig_dsa_sha512_oid, required_size);
		break;
	case X509_SIG_DSA_SHA3_224:
		memcpy(buffer, x509_sig_dsa_sha3_224_oid, required_size);
		break;
	case X509_SIG_DSA_SHA3_256:
		memcpy(buffer, x509_sig_dsa_sha3_256_oid, required_size);
		break;
	case X509_SIG_DSA_SHA3_384:
		memcpy(buffer, x509_sig_dsa_sha3_384_oid, required_size);
		break;
	case X509_SIG_DSA_SHA3_512:
		memcpy(buffer, x509_sig_dsa_sha3_512_oid, required_size);
		break;

	// ECDSA
	case X509_SIG_ECDSA_SHA1:
		memcpy(buffer, x509_sig_ecdsa_sha1_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHA224:
		memcpy(buffer, x509_sig_ecdsa_sha224_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHA256:
		memcpy(buffer, x509_sig_ecdsa_sha256_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHA384:
		memcpy(buffer, x509_sig_ecdsa_sha384_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHA512:
		memcpy(buffer, x509_sig_ecdsa_sha512_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHA3_224:
		memcpy(buffer, x509_sig_ecdsa_sha3_224_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHA3_256:
		memcpy(buffer, x509_sig_ecdsa_sha3_256_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHA3_384:
		memcpy(buffer, x509_sig_ecdsa_sha3_384_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHA3_512:
		memcpy(buffer, x509_sig_ecdsa_sha3_512_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHAKE128:
		memcpy(buffer, x509_sig_ecdsa_shake128_oid, required_size);
		break;
	case X509_SIG_ECDSA_SHAKE256:
		memcpy(buffer, x509_sig_ecdsa_shake256_oid, required_size);
		break;

	case X509_SIG_ED25519:
		memcpy(buffer, x509_ed25519_oid, required_size);
		break;
	case X509_SIG_ED448:
		memcpy(buffer, x509_ed448_oid, required_size);
		break;

	// MLDSA
	case X509_SIG_MLDSA_44:
		memcpy(buffer, x509_sig_mldsa_44_oid, required_size);
		break;
	case X509_SIG_MLDSA_65:
		memcpy(buffer, x509_sig_mldsa_65_oid, required_size);
		break;
	case X509_SIG_MLDSA_87:
		memcpy(buffer, x509_sig_mldsa_87_oid, required_size);
		break;
	case X509_SIG_HASH_MLDSA_44:
		memcpy(buffer, x509_sig_hash_mldsa_44_oid, required_size);
		break;
	case X509_SIG_HASH_MLDSA_65:
		memcpy(buffer, x509_sig_hash_mldsa_65_oid, required_size);
		break;
	case X509_SIG_HASH_MLDSA_87:
		memcpy(buffer, x509_sig_hash_mldsa_87_oid, required_size);
		break;
	}

	return required_size;
}

x509_signature_algorithm x509_signature_oid_decode(byte_t *oid, uint32_t size)
{
	if (size == 0)
	{
		return X509_SIG_RESERVED;
	}

	if (oid[0] == 0x2A)
	{
		if (size == 7)
		{
			if (oid[1] == 0x86 && oid[2] == 0x48 && oid[3] == 0xCE && oid[5] == 0x04)
			{
				if (oid[4] == 0x38 && oid[6] == 0x03)
				{
					return X509_SIG_DSA_SHA1;
				}

				if (oid[4] == 0x3D && oid[6] == 0x01)
				{
					return X509_SIG_ECDSA_SHA1;
				}
			}
		}

		if (size == 8)
		{
			if (memcmp(oid + 1, x509_sig_ecdsa_sha224_oid + 1, 6) == 0)
			{
				switch (oid[7])
				{
				case 0x01:
					return X509_SIG_ECDSA_SHA224;
				case 0x02:
					return X509_SIG_ECDSA_SHA256;
				case 0x03:
					return X509_SIG_ECDSA_SHA384;
				case 0x04:
					return X509_SIG_ECDSA_SHA512;
				}
			}
		}

		// RSA
		if (size == 9)
		{
			if (memcmp(oid + 1, x509_sig_rsa_pkcs_md5_oid + 1, 7) == 0)
			{
				switch (oid[8])
				{
				case 0x04:
					return X509_SIG_RSA_PKCS_MD5;
				case 0x05:
					return X509_SIG_RSA_PKCS_SHA1;
				case 0x0A:
					return X509_SIG_RSA_PSS;
				case 0x0B:
					return X509_SIG_RSA_PKCS_SHA256;
				case 0x0C:
					return X509_SIG_RSA_PKCS_SHA384;
				case 0x0D:
					return X509_SIG_RSA_PKCS_SHA512;
				case 0x0E:
					return X509_SIG_RSA_PKCS_SHA224;
				}
			}
		}
	}

	if (oid[0] == 0x2B)
	{
		if (size == 3)
		{
			if (oid[1] == 0x65)
			{
				switch (oid[2])
				{
				case 0x70:
					return X509_SIG_ED25519;
				case 0x71:
					return X509_SIG_ED448;
				}
			}
		}

		if (size == 8)
		{
			if (memcmp(oid + 1, x509_sig_ecdsa_shake256_oid + 1, 6) == 0)
			{
				switch (oid[7])
				{
				case 0x1E:
					return X509_SIG_RSA_PSS_SHAKE128;
				case 0x1F:
					return X509_SIG_RSA_PSS_SHAKE256;
				case 0x20:
					return X509_SIG_ECDSA_SHAKE128;
				case 0x21:
					return X509_SIG_ECDSA_SHAKE256;
				}
			}
		}
	}

	// NIST
	if (oid[0] == 0x60)
	{
		if (size == 9)
		{
			if (memcmp(oid + 1, x509_sig_rsa_pkcs_sha3_224_oid + 1, 7) == 0)
			{
				switch (oid[8])
				{
				case 0x01:
					return X509_SIG_DSA_SHA224;
				case 0x02:
					return X509_SIG_DSA_SHA256;
				case 0x03:
					return X509_SIG_DSA_SHA384;
				case 0x04:
					return X509_SIG_DSA_SHA512;
				case 0x05:
					return X509_SIG_DSA_SHA3_224;
				case 0x06:
					return X509_SIG_DSA_SHA3_256;
				case 0x07:
					return X509_SIG_DSA_SHA3_384;
				case 0x08:
					return X509_SIG_DSA_SHA3_512;
				case 0x09:
					return X509_SIG_ECDSA_SHA3_224;
				case 0x0A:
					return X509_SIG_ECDSA_SHA3_256;
				case 0x0B:
					return X509_SIG_ECDSA_SHA3_384;
				case 0x0C:
					return X509_SIG_ECDSA_SHA3_512;
				case 0x0D:
					return X509_SIG_RSA_PKCS_SHA3_224;
				case 0x0E:
					return X509_SIG_RSA_PKCS_SHA3_256;
				case 0x0F:
					return X509_SIG_RSA_PKCS_SHA3_384;
				case 0x10:
					return X509_SIG_RSA_PKCS_SHA3_512;
				case 0x11:
					return X509_SIG_MLDSA_44;
				case 0x12:
					return X509_SIG_MLDSA_65;
				case 0x13:
					return X509_SIG_MLDSA_87;
				case 0x20:
					return X509_SIG_HASH_MLDSA_44;
				case 0x21:
					return X509_SIG_HASH_MLDSA_65;
				case 0x22:
					return X509_SIG_HASH_MLDSA_87;
				}
			}
		}
	}

	return X509_SIG_RESERVED;
}

// Refer RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation

// NIST
// Prime curves
const byte_t x509_ec_nist_p192_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01};
const byte_t x509_ec_nist_p224_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x21};
const byte_t x509_ec_nist_p256_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
const byte_t x509_ec_nist_p384_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x22};
const byte_t x509_ec_nist_p521_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x23};

// Binary curves
const byte_t x509_ec_nist_k163_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x01};
const byte_t x509_ec_nist_b163_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x0F};
const byte_t x509_ec_nist_k233_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x1A};
const byte_t x509_ec_nist_b233_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x1B};
const byte_t x509_ec_nist_k283_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x10};
const byte_t x509_ec_nist_b283_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x11};
const byte_t x509_ec_nist_k409_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x24};
const byte_t x509_ec_nist_b409_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x25};
const byte_t x509_ec_nist_k571_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x26};
const byte_t x509_ec_nist_b571_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x27};

// SEC
// Prime curves
const byte_t x509_ec_secp_160k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x09};
const byte_t x509_ec_secp_160r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x08};
const byte_t x509_ec_secp_160r2_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x1E};
const byte_t x509_ec_secp_192k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x1F};
const byte_t x509_ec_secp_192r1_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01};
const byte_t x509_ec_secp_224k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x20};
const byte_t x509_ec_secp_224r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x21};
const byte_t x509_ec_secp_256k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x0A};
const byte_t x509_ec_secp_256r1_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
const byte_t x509_ec_secp_384r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x22};
const byte_t x509_ec_secp_521r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x23};

// Binary curves
const byte_t x509_ec_sect_163k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x01};
const byte_t x509_ec_sect_163r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x02};
const byte_t x509_ec_sect_163r2_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x0F};
const byte_t x509_ec_sect_193r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x18};
const byte_t x509_ec_sect_193r2_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x19};
const byte_t x509_ec_sect_233k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x1A};
const byte_t x509_ec_sect_233r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x1B};
const byte_t x509_ec_sect_239k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x03};
const byte_t x509_ec_sect_283k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x10};
const byte_t x509_ec_sect_283r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x11};
const byte_t x509_ec_sect_409k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x24};
const byte_t x509_ec_sect_409r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x25};
const byte_t x509_ec_sect_571k1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x26};
const byte_t x509_ec_sect_571r1_oid[] = {0x2B, 0x81, 0x04, 0x00, 0x27};

// Brainpool
const byte_t x509_ec_brainpool_160r1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01};
const byte_t x509_ec_brainpool_160t1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x02};
const byte_t x509_ec_brainpool_192r1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03};
const byte_t x509_ec_brainpool_192t1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x04};
const byte_t x509_ec_brainpool_224r1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05};
const byte_t x509_ec_brainpool_224t1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x06};
const byte_t x509_ec_brainpool_256r1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
const byte_t x509_ec_brainpool_256t1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08};
const byte_t x509_ec_brainpool_320r1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09};
const byte_t x509_ec_brainpool_320t1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0A};
const byte_t x509_ec_brainpool_384r1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B};
const byte_t x509_ec_brainpool_384t1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0C};
const byte_t x509_ec_brainpool_512r1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D};
const byte_t x509_ec_brainpool_512t1_oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0E};

// Montgomery and Edwards
const byte_t x509_ec_curve25519_oid[] = {0x2B, 0x65, 0x6E};
const byte_t x509_ec_curve448_oid[] = {0x2B, 0x65, 0x6F};
const byte_t x509_ec_ed25519_oid[] = {0x2B, 0x65, 0x70};
const byte_t x509_ec_ed448_oid[] = {0x2B, 0x65, 0x71};

uint32_t x509_curve_oid_size(x509_curve_id id)
{
	switch (id)
	{
	case X509_EC_RESERVED:
		return 0;

	// NIST
	// Prime curves
	case X509_EC_NIST_P192:
	case X509_EC_NIST_P256:
		return 8;
	case X509_EC_NIST_P224:
	case X509_EC_NIST_P384:
	case X509_EC_NIST_P521:
		return 5;

	// Binary curves
	case X509_EC_NIST_K163:
	case X509_EC_NIST_B163:
	case X509_EC_NIST_K233:
	case X509_EC_NIST_B233:
	case X509_EC_NIST_K283:
	case X509_EC_NIST_B283:
	case X509_EC_NIST_K409:
	case X509_EC_NIST_B409:
	case X509_EC_NIST_K571:
	case X509_EC_NIST_B571:
		return 5;

	// SEC
	// Prime curves
	case X509_EC_SECP_192R1:
	case X509_EC_SECP_256R1:
		return 8;
	case X509_EC_SECP_160K1:
	case X509_EC_SECP_160R1:
	case X509_EC_SECP_160R2:
	case X509_EC_SECP_192K1:
	case X509_EC_SECP_224K1:
	case X509_EC_SECP_224R1:
	case X509_EC_SECP_256K1:
	case X509_EC_SECP_384R1:
	case X509_EC_SECP_521R1:
		return 5;

	// Binary curves
	case X509_EC_SECT_163K1:
	case X509_EC_SECT_163R1:
	case X509_EC_SECT_163R2:
	case X509_EC_SECT_193R1:
	case X509_EC_SECT_193R2:
	case X509_EC_SECT_233K1:
	case X509_EC_SECT_233R1:
	case X509_EC_SECT_239K1:
	case X509_EC_SECT_283K1:
	case X509_EC_SECT_283R1:
	case X509_EC_SECT_409K1:
	case X509_EC_SECT_409R1:
	case X509_EC_SECT_571K1:
	case X509_EC_SECT_571R1:
		return 5;

	// Brainpool
	case X509_EC_BRAINPOOL_160R1:
	case X509_EC_BRAINPOOL_160T1:
	case X509_EC_BRAINPOOL_192R1:
	case X509_EC_BRAINPOOL_192T1:
	case X509_EC_BRAINPOOL_224R1:
	case X509_EC_BRAINPOOL_224T1:
	case X509_EC_BRAINPOOL_256R1:
	case X509_EC_BRAINPOOL_256T1:
	case X509_EC_BRAINPOOL_320R1:
	case X509_EC_BRAINPOOL_320T1:
	case X509_EC_BRAINPOOL_384R1:
	case X509_EC_BRAINPOOL_384T1:
	case X509_EC_BRAINPOOL_512R1:
	case X509_EC_BRAINPOOL_512T1:
		return 9;

	// Montgomery and Edwards
	case X509_EC_CURVE25519:
	case X509_EC_CURVE448:
	case X509_EC_ED25519:
	case X509_EC_ED448:
		return 3;
	}

	return 0;
}

x509_curve_id x509_curve_oid_decode(byte_t *oid, uint32_t size)
{
	if (size == 0)
	{
		return X509_EC_RESERVED;
	}

	// Standard curves
	if (oid[0] == 0x2B)
	{
		// NIST and SEC
		if (size == 5)
		{
			if (oid[1] == 0x81 && oid[2] == 0x04 && oid[3] == 0x00)
			{
				switch (oid[4])
				{
				case 0x01:
					return X509_EC_NIST_K163;
				case 0x02:
					return X509_EC_SECT_163R1;
				case 0x03:
					return X509_EC_SECT_239K1;
				case 0x08:
					return X509_EC_SECP_160R1;
				case 0x09:
					return X509_EC_SECP_160K1;
				case 0x0A:
					return X509_EC_SECP_256K1;
				case 0x0F:
					return X509_EC_NIST_B163;
				case 0x10:
					return X509_EC_NIST_K283;
				case 0x11:
					return X509_EC_NIST_B283;
				case 0x18:
					return X509_EC_SECT_193R1;
				case 0x19:
					return X509_EC_SECT_193R2;
				case 0x1A:
					return X509_EC_NIST_K233;
				case 0x1B:
					return X509_EC_NIST_B233;
				case 0x1E:
					return X509_EC_SECP_160R2;
				case 0x1F:
					return X509_EC_SECP_192K1;
				case 0x20:
					return X509_EC_SECP_224K1;
				case 0x21:
					return X509_EC_NIST_P224;
				case 0x22:
					return X509_EC_NIST_P384;
				case 0x23:
					return X509_EC_NIST_P521;
				case 0x24:
					return X509_EC_NIST_K409;
				case 0x25:
					return X509_EC_NIST_B409;
				case 0x26:
					return X509_EC_NIST_K571;
				case 0x27:
					return X509_EC_NIST_B571;
				}
			}
		}

		if (size == 9)
		{
			if (memcmp(oid + 1, x509_ec_brainpool_160r1_oid + 1, 7) == 0)
			{
				switch (oid[8])
				{
				case 0x01:
					return X509_EC_BRAINPOOL_160R1;
				case 0x02:
					return X509_EC_BRAINPOOL_160T1;
				case 0x03:
					return X509_EC_BRAINPOOL_192R1;
				case 0x04:
					return X509_EC_BRAINPOOL_192T1;
				case 0x05:
					return X509_EC_BRAINPOOL_224R1;
				case 0x06:
					return X509_EC_BRAINPOOL_224T1;
				case 0x07:
					return X509_EC_BRAINPOOL_256R1;
				case 0x08:
					return X509_EC_BRAINPOOL_256T1;
				case 0x09:
					return X509_EC_BRAINPOOL_320R1;
				case 0x0A:
					return X509_EC_BRAINPOOL_320T1;
				case 0x0B:
					return X509_EC_BRAINPOOL_384R1;
				case 0x0C:
					return X509_EC_BRAINPOOL_384T1;
				case 0x0D:
					return X509_EC_BRAINPOOL_512R1;
				case 0x0E:
					return X509_EC_BRAINPOOL_512T1;
				}
			}
		}

		// Montgomery and Edwards
		if (size == 3)
		{
			if (oid[1] == 0x65)
			{

				switch (oid[2])
				{
				case 0x6E:
					return X509_EC_CURVE25519;
				case 0x6F:
					return X509_EC_CURVE448;
				case 0x70:
					return X509_EC_ED25519;
				case 0x71:
					return X509_EC_ED448;
				}
			}
		}
	}

	// Outliers NIST-P192, NIST-P256
	if (oid[0] == 0x2A)
	{
		if (size == 8)
		{

			if (memcmp(oid + 1, x509_ec_nist_p192_oid + 1, 6) == 0)
			{
				switch (oid[7])
				{
				case 0x01:
					return X509_EC_NIST_P192;
				case 0x07:
					return X509_EC_NIST_P256;
				}
			}
		}
	}

	return X509_EC_RESERVED;
}

// Refer RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
const byte_t x509_rdn_common_name_oid[] = {0x55, 0x04, 0x03};
const byte_t x509_rdn_surname_oid[] = {0x55, 0x04, 0x04};
const byte_t x509_rdn_name_oid[] = {0x55, 0x04, 0x29};
const byte_t x509_rdn_given_name_oid[] = {0x55, 0x04, 0x2A};
const byte_t x509_rdn_initials_oid[] = {0x55, 0x04, 0x2B};
const byte_t x509_rdn_generation_qualifier_oid[] = {0x55, 0x04, 0x2C};

const byte_t x509_rdn_locality_name_oid[] = {0x55, 0x04, 0x07};
const byte_t x509_rdn_state_province_name_oid[] = {0x55, 0x04, 0x08};
const byte_t x509_rdn_organization_name_oid[] = {0x55, 0x04, 0x0A};
const byte_t x509_rdn_organizational_unit_name_oid[] = {0x55, 0x04, 0x0B};

const byte_t x509_rdn_title_oid[] = {0x55, 0x04, 0x0C};
const byte_t x509_rdn_serial_number_oid[] = {0x55, 0x04, 0x05};
const byte_t x509_rdn_country_name_oid[] = {0x55, 0x04, 0x06};
const byte_t x509_rdn_dn_qualifier_oid[] = {0x55, 0x04, 0x2E};
const byte_t x509_rdn_pseudonym_oid[] = {0x55, 0x04, 0x41};
const byte_t x509_rdn_domain_component_oid[] = {0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19};
const byte_t x509_rdn_email_addres_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01};

x509_rdn_type x509_rdn_oid_decode(byte_t *oid, uint32_t size)
{
	if (size == 3)
	{
		if (oid[0] == 0x55 && oid[1] == 0x04)
		{
			switch (oid[2])
			{
			case 0x03:
				return X509_RDN_COMMON_NAME;
			case 0x04:
				return X509_RDN_SURNAME;
			case 0x05:
				return X509_RDN_SERIAL_NUMBER;
			case 0x06:
				return X509_RDN_COUNTRY_NAME;
			case 0x07:
				return X509_RDN_LOCALITY_NAME;
			case 0x08:
				return X509_RDN_STATE_PROVINCE_NAME;
			case 0x0A:
				return X509_RDN_ORGANIZATION_NAME;
			case 0x0B:
				return X509_RDN_ORGANIZATIONAL_UNIT_NAME;
			case 0x0C:
				return X509_RDN_TITLE;
			case 0x29:
				return X509_RDN_NAME;
			case 0x2A:
				return X509_RDN_GIVEN_NAME;
			case 0x2B:
				return X509_RDN_INITIALS;
			case 0x2C:
				return X509_RDN_GENERATION_QUALIFIER;
			case 0x2E:
				return X509_RDN_DN_QUALIFIER;
			case 0x41:
				return X509_RDN_PSEUDONYM;
			}
		}
	}

	if (size == 10)
	{
		if (memcmp(oid, x509_rdn_domain_component_oid, 10) == 0)
		{
			return X509_RDN_DOMAIN_COMPONENT;
		}

		if (memcmp(oid, x509_rdn_email_addres_oid, 10) == 0)
		{
			return X509_RDN_EMAIL_ADDRESS;
		}
	}

	return X509_RDN_RESERVED;
}

const byte_t x509_ext_subject_directory_attributes_oid[] = {0x55, 0x1D, 0x09};
const byte_t x509_ext_subject_key_identifier_oid[] = {0x55, 0x1D, 0x0E};
const byte_t x509_ext_key_usage_oid[] = {0x55, 0x1D, 0x0F};
const byte_t x509_ext_private_key_usage_period_oid[] = {0x55, 0x1D, 0x10};
const byte_t x509_ext_subject_alternate_name_oid[] = {0x55, 0x1D, 0x11};
const byte_t x509_ext_issuer_alternate_name_oid[] = {0x55, 0x1D, 0x12};
const byte_t x509_ext_basic_constraints_oid[] = {0x55, 0x1D, 0x13};
const byte_t x509_ext_name_constraints_oid[] = {0x55, 0x1D, 0x1E};
const byte_t x509_ext_crl_distribution_points_oid[] = {0x55, 0x1D, 0x1F};
const byte_t x509_ext_certificate_policies_oid[] = {0x55, 0x1D, 0x20};
const byte_t x509_ext_policy_mappings_oid[] = {0x55, 0x1D, 0x21};
const byte_t x509_ext_authority_key_identifier_oid[] = {0x55, 0x1D, 0x23};
const byte_t x509_ext_policy_constraints_oid[] = {0x55, 0x1D, 0x24};
const byte_t x509_ext_extended_key_usage_oid[] = {0x55, 0x1D, 0x25};
const byte_t x509_ext_delta_crl_distribution_points_oid[] = {0x55, 0x1D, 0x2E};
const byte_t x509_ext_inhibit_anypolicy_oid[] = {0x55, 0x1D, 0x36};

const byte_t x509_ext_authority_information_access_oid[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01};
const byte_t x509_ext_subject_information_access_oid[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0B};

x509_extension_type x509_extension_oid_decode(byte_t *oid, uint32_t size)
{
	if (size == 3)
	{
		if (oid[0] == 0x55 && oid[1] == 0x1D)
		{
			switch (oid[2])
			{
			case 0x09:
				return X509_EXT_SUBJECT_DIRECTORY_ATTRIBUTES;
			case 0x0E:
				return X509_EXT_SUBJECT_KEY_IDENTIFIER;
			case 0x0F:
				return X509_EXT_KEY_USAGE;
			case 0x10:
				return X509_EXT_PRIVATE_KEY_USAGE_PERIOD;
			case 0x11:
				return X509_EXT_SUBJECT_ALTERNATE_NAME;
			case 0x12:
				return X509_EXT_ISSUER_ALTERNATE_NAME;
			case 0x13:
				return X509_EXT_BASIC_CONSTRAINTS;
			case 0x1E:
				return X509_EXT_NAME_CONSTRAINTS;
			case 0x1F:
				return X509_EXT_CRL_DISTRIBUTION_POINTS;
			case 0x20:
				return X509_EXT_CERTIFICATE_POLICIES;
			case 0x21:
				return X509_EXT_POLICY_MAPPINGS;
			case 0x23:
				return X509_EXT_AUTHORITY_KEY_IDENTIFIER;
			case 0x24:
				return X509_EXT_POLICY_CONSTRAINTS;
			case 0x25:
				return X509_EXT_EXTENDED_KEY_USAGE;
			case 0x2E:
				return X509_EXT_DELTA_CRL_DISTRIBUTION_POINTS;
			case 0x36:
				return X509_EXT_INHIBIT_ANYPOLICY;
			}
		}
	}

	if (size == 8)
	{
		if (memcmp(oid, x509_ext_authority_information_access_oid, 7) == 0)
		{
			if (oid[7] == 0x01)
			{
				return X509_EXT_AUTHORITY_INFORMATION_ACCESS;
			}

			if (oid[7] == 0x0B)
			{
				return X509_EXT_SUBJECT_INFORMATION_ACCESS;
			}
		}
	}

	return X509_EXT_RESERVED;
}

static uint32_t base128_encode(byte_t *buffer, uint32_t size, uint64_t value)
{
	byte_t temp[16] = {0};
	byte_t pos = 0;
	byte_t result = 0;

	do
	{
		temp[pos++] = value % 128;
		value /= 128;

	} while (value != 0);

	result = pos;

	while (pos != 0)
	{
		if (size > 0)
		{
			*buffer++ = temp[pos - 1] | (pos > 1 ? 0x80 : 0x00);
			--size;
		}

		--pos;
	}

	return result;
}

static uint32_t base128_decode(byte_t *buffer, uint32_t size, uint64_t value)
{
	byte_t temp[32] = {0};
	byte_t pos = 0;
	byte_t result = 0;

	do
	{
		temp[pos++] = value % 10;
		value /= 10;

	} while (value != 0);

	result = pos;

	while (pos != 0)
	{
		if (size > 0)
		{
			*buffer++ = temp[pos - 1] + '0';
			--size;
		}

		--pos;
	}

	return result;
}

uint32_t oid_encode(void *buffer, uint32_t buffer_size, void *oid, uint32_t oid_size)
{
	byte_t *in = oid;
	byte_t *out = buffer;

	uint32_t in_pos = 0;
	uint32_t out_pos = 0;
	uint32_t result = 0;

	uint64_t component = 0;
	uint64_t first = 0;
	uint32_t count = 0;

	byte_t digit = 0;

	// Minimum size is 3. eg 1.0, 0.2 ...
	if (oid_size < 3)
	{
		return 0;
	}

	while (in_pos < oid_size)
	{
		if (*in >= '0' && *in <= '9')
		{
			component = (component * 10) + (*in - '0');
			in++;
			in_pos++;

			digit = 1;

			continue;
		}

		if (*in == '.')
		{
			// Catch 1..
			if (digit == 0)
			{
				return 0;
			}

			in++;
			in_pos++;
			count++;

			if (count == 1)
			{
				first = component;
				component = 0;
				digit = 0;

				if (first > 2)
				{
					return 0;
				}

				continue;
			}

			if (count == 2)
			{
				if (first < 2)
				{
					if (component >= 40)
					{
						return 0;
					}
				}

				component = (first * 40) + component;
			}

			result += base128_encode(out + out_pos, buffer_size - out_pos, component);
			out_pos = MIN(buffer_size, result);

			component = 0;
			digit = 0;

			continue;
		}

		return 0;
	}

	// Atleast 2 components
	if (count == 0)
	{
		return 0;
	}

	// Trailing dot
	if (digit == 0)
	{
		return 0;
	}

	if (count < 2)
	{
		if (first < 2)
		{
			if (component >= 40)
			{
				return 0;
			}
		}

		component = (first * 40) + component;
	}

	result += base128_encode(out + out_pos, buffer_size - out_pos, component);
	out_pos = MIN(buffer_size, out_pos + result);

	return result;
}

uint32_t oid_decode(void *oid, uint32_t oid_size, void *buffer, uint32_t buffer_size)
{
	byte_t *in = buffer;
	byte_t *out = oid;

	uint32_t pos = 0;
	uint32_t result = 0;

	uint64_t component = 0;
	byte_t arc = 0;
	byte_t last = 0;

	while (pos < buffer_size)
	{
		last = 0;

		while (pos < buffer_size)
		{
			component = (component << 7) + (*in & 0x7F);

			if (*in < 128)
			{
				++in;
				++pos;
				last = 1;

				break;
			}

			++in;
			++pos;
		}

		if (arc == 0)
		{

			if (component < 40)
			{
				arc = '0';
			}
			else if (component < 80)
			{
				arc = '1';
				component -= 40;
			}
			else
			{
				arc = '2';
				component -= 80;
			}

			if (oid_size > 0)
			{
				*out++ = arc;
				--oid_size;
			}

			++result;
		}

		if (last)
		{
			if (oid_size > 0)
			{
				*out++ = ',';
				--oid_size;
			}

			++result;

			result += base128_decode(out, oid_size, component);

			component = 0;
		}
	}

	if (last == 0)
	{
		return 0;
	}

	return result;
}
