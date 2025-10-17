/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <scrypt.h>
#include <test.h>

// See RFC 7914 : The scrypt Password-Based Key Derivation Function

int32_t scrypt_test_suite(void)
{
	int32_t status = 0;
	byte_t key[64];

	scrypt("", 0, "", 0, 16, 1, 1, key, 64);
	status += CHECK_BLOCK(
		key, 64,
		"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");

	scrypt("password", 8, "NaCl", 4, 1024, 8, 16, key, 64);
	status += CHECK_BLOCK(
		key, 64,
		"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");

	scrypt("pleaseletmein", 13, "SodiumChloride", 14, 16384, 8, 1, key, 64);
	status += CHECK_BLOCK(
		key, 64,
		"7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");

	return status;
}

int main()
{
	return scrypt_test_suite();
}
