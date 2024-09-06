/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>

#include <pbkdf2.h>
#include <test.h>

// See RFC 6070 : PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors

int32_t pbkdf2_sha1_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];

	pbkdf2(HMAC_SHA1, "password", 8, "salt", 4, 1, key, 20);
	status += CHECK_BLOCK(key, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6");

	pbkdf2(HMAC_SHA1, "password", 8, "salt", 4, 2, key, 20);
	status += CHECK_BLOCK(key, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");

	pbkdf2(HMAC_SHA1, "password", 8, "salt", 4, 4096, key, 20);
	status += CHECK_BLOCK(key, 20, "4b007901b765489abead49d926f721d065a429c1");

	pbkdf2(HMAC_SHA1, "passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, key, 25);
	status += CHECK_BLOCK(key, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");

	pbkdf2(HMAC_SHA1, "pass\0word", 9, "sa\0lt", 5, 4096, key, 16);
	status += CHECK_BLOCK(key, 16, "56fa6aa75548099dcc37d7f03425e0c3");

	return status;
}

int main()
{
	return pbkdf2_sha1_test_suite();
}
