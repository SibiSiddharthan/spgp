/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pbkdf2.h>
#include <test.h>

// See RFC 6070 : PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors
// See RFC 7914 : The scrypt Password-Based Key Derivation Function, Section 11

int32_t pbkdf2_sha1_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];

	pbkdf2(HASH_SHA1, "password", 8, "salt", 4, 1, key, 20);
	status += CHECK_BLOCK(key, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6");

	pbkdf2(HASH_SHA1, "password", 8, "salt", 4, 2, key, 20);
	status += CHECK_BLOCK(key, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");

	pbkdf2(HASH_SHA1, "password", 8, "salt", 4, 4096, key, 20);
	status += CHECK_BLOCK(key, 20, "4b007901b765489abead49d926f721d065a429c1");

	pbkdf2(HASH_SHA1, "passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, key, 25);
	status += CHECK_BLOCK(key, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");

	pbkdf2(HASH_SHA1, "pass\0word", 9, "sa\0lt", 5, 4096, key, 16);
	status += CHECK_BLOCK(key, 16, "56fa6aa75548099dcc37d7f03425e0c3");

	return status;
}

int32_t pbkdf2_sha256_test_suite(void)
{
	int32_t status = 0;
	byte_t key[64];

	pbkdf2(HASH_SHA256, "passwd", 6, "salt", 4, 1, key, 64);
	status += CHECK_BLOCK(
		key, 64,
		"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");

	pbkdf2(HASH_SHA256, "Password", 8, "NaCl", 4, 80000, key, 64);
	status += CHECK_BLOCK(
		key, 64,
		"4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d");

	return status;
}

int main()
{
	return pbkdf2_sha1_test_suite() + pbkdf2_sha256_test_suite();
}
