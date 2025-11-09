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

const byte_t x509_dsa_oid[] = {0X2A, 0X86, 0X48, 0XCE, 0X38, 0X04, 0X01};

const byte_t x509_ecdsa_oid[] = {0X2A, 0X86, 0X48, 0XCE, 0X3D, 0X02, 0X01};
const byte_t x509_ecdh_oid[] = {0X2B, 0X81, 0X04, 0X01, 0X0C};
const byte_t x509_ecmqv_oid[] = {0X2B, 0X81, 0X04, 0X01, 0X0D};

const byte_t x509_rsa_pkcs_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X01};
const byte_t x509_rsa_oaep_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X07};
const byte_t x509_rsa_pss_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X0A};

const byte_t x509_x25519_oid[] = {0X2B, 0X65, 0X6E};
const byte_t x509_x448_oid[] = {0X2B, 0X65, 0X6F};
const byte_t x509_ed25519_oid[] = {0X2B, 0X65, 0X70};
const byte_t x509_ed448_oid[] = {0X2B, 0X65, 0X71};

const byte_t x509_rsa_pkcs_md5_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X04};
const byte_t x509_rsa_pkcs_sha1_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X05};
const byte_t x509_rsa_pkcs_sha224_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X0E};
const byte_t x509_rsa_pkcs_sha256_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X0B};
const byte_t x509_rsa_pkcs_sha384_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X0C};
const byte_t x509_rsa_pkcs_sha512_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X0D};
const byte_t x509_rsa_pkcs_sha3_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0D};
const byte_t x509_rsa_pkcs_sha3_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0E};
const byte_t x509_rsa_pkcs_sha3_384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0F};
const byte_t x509_rsa_pkcs_sha3_512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10};

const byte_t x509_rsa_pss_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X0A};
const byte_t x509_rsa_pss_shake128_oid[] = {0X2B, 0X06, 0X01, 0X05, 0X05, 0X07, 0X06, 0X1E};
const byte_t x509_rsa_pss_shake256_oid[] = {0X2B, 0X06, 0X01, 0X05, 0X05, 0X07, 0X06, 0X1F};

const byte_t x509_dsa_sha1_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03};
const byte_t x509_dsa_sha224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01};
const byte_t x509_dsa_sha256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02};
const byte_t x509_dsa_sha384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03};
const byte_t x509_dsa_sha512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04};
const byte_t x509_dsa_sha3_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x05};
const byte_t x509_dsa_sha3_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x06};
const byte_t x509_dsa_sha3_384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x07};
const byte_t x509_dsa_sha3_512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x08};

const byte_t x509_ecdsa_sha1_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01};
const byte_t x509_ecdsa_sha224_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01};
const byte_t x509_ecdsa_sha256_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
const byte_t x509_ecdsa_sha384_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
const byte_t x509_ecdsa_sha512_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};
const byte_t x509_ecdsa_sha3_224_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09};
const byte_t x509_ecdsa_sha3_256_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0A};
const byte_t x509_ecdsa_sha3_384_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0B};
const byte_t x509_ecdsa_sha3_512_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0C};
const byte_t x509_ecdsa_shake128_oid[] = {0X2B, 0X06, 0X01, 0X05, 0X05, 0X07, 0X06, 0X20};
const byte_t x509_ecdsa_shake256_oid[] = {0X2B, 0X06, 0X01, 0X05, 0X05, 0X07, 0X06, 0X21};

const byte_t x509_ed25519_oid[] = {0X2B, 0X65, 0X70};
const byte_t x509_ed448_oid[] = {0X2B, 0X65, 0X71};

const byte_t x509_mldsa_44_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};
const byte_t x509_mldsa_65_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
const byte_t x509_mldsa_87_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};
const byte_t x509_hash_mldsa_44_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x20};
const byte_t x509_hash_mldsa_65_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x21};
const byte_t x509_hash_mldsa_87_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x22};

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

// Refer RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
const byte_t x509_rdn_common_name_oid[] = {0X55, 0X04, 0X03};
const byte_t x509_rdn_surname_oid[] = {0X55, 0X04, 0X04};
const byte_t x509_rdn_name_oid[] = {0X55, 0X04, 0X29};
const byte_t x509_rdn_given_name_oid[] = {0X55, 0X04, 0X2A};
const byte_t x509_rdn_initials_oid[] = {0X55, 0X04, 0X2B};
const byte_t x509_rdn_generation_qualifier_oid[] = {0X55, 0X04, 0X2C};

const byte_t x509_rdn_locality_name_oid[] = {0X55, 0X04, 0X07};
const byte_t x509_rdn_state_province_name_oid[] = {0X55, 0X04, 0X08};
const byte_t x509_rdn_organization_name_oid[] = {0X55, 0X04, 0X0A};
const byte_t x509_rdn_organizational_unit_name_oid[] = {0X55, 0X04, 0X0B};

const byte_t x509_rdn_title_oid[] = {0X55, 0X04, 0X0C};
const byte_t x509_rdn_serial_number_oid[] = {0X55, 0X04, 0X05};
const byte_t x509_rdn_country_name_oid[] = {0X55, 0X04, 0X06};
const byte_t x509_rdn_dn_qualifier_oid[] = {0X55, 0X04, 0X2E};
const byte_t x509_rdn_pseudonym_oid[] = {0X55, 0X04, 0X41};
const byte_t x509_rdn_domain_component_oid[] = {0X09, 0X92, 0X26, 0X89, 0X93, 0XF2, 0X2C, 0X64, 0X01, 0X19};
const byte_t x509_rdn_email_addres_oid[] = {0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X09, 0X01};

const byte_t x509_ext_subject_directory_attributes_oid[] = {0X55, 0X1D, 0X09};
const byte_t x509_ext_subject_key_identifier_oid[] = {0X55, 0X1D, 0X0E};
const byte_t x509_ext_key_usage_oid[] = {0X55, 0X1D, 0X0F};
const byte_t x509_ext_private_key_usage_period_oid[] = {0X55, 0X1D, 0X10};
const byte_t x509_ext_subject_alternate_name_oid[] = {0X55, 0X1D, 0X11};
const byte_t x509_ext_issuer_alternate_name_oid[] = {0X55, 0X1D, 0X12};
const byte_t x509_ext_basic_constraints_oid[] = {0X55, 0X1D, 0X13};
const byte_t x509_ext_name_constraints_oid[] = {0X55, 0X1D, 0X1E};
const byte_t x509_ext_crl_distribution_points_oid[] = {0X55, 0X1D, 0X1F};
const byte_t x509_ext_certificate_policies_oid[] = {0X55, 0X1D, 0X20};
const byte_t x509_ext_policy_mappings_oid[] = {0X55, 0X1D, 0X21};
const byte_t x509_ext_authority_key_identifier_oid[] = {0X55, 0X1D, 0X23};
const byte_t x509_ext_policy_constraints_oid[] = {0X55, 0X1D, 0X24};
const byte_t x509_ext_extended_key_usage_oid[] = {0X55, 0X1D, 0X25};
const byte_t x509_ext_delta_crl_distribution_points_oid[] = {0X55, 0X1D, 0X2E};
const byte_t x509_ext_inhibit_anypolicy_oid[] = {0X55, 0X1D, 0X36};

const byte_t x509_ext_authority_information_access_oid[] = {0X2B, 0X06, 0X01, 0X05, 0X05, 0X07, 0X01, 0X01};
const byte_t x509_ext_subject_information_access_oid[] = {0X2B, 0X06, 0X01, 0X05, 0X05, 0X07, 0X01, 0X0B};

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
