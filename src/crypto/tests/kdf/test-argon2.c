/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <argon2.h>
#include <test.h>

// See RFC 9106 : PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors

int32_t argon2_test_suite(void)
{
	int32_t status = 0;

	byte_t password[32];
	byte_t salt[32];
	byte_t secret[32];
	byte_t data[32];
	byte_t key[32];

	// -------------------------------------------------------------------------------------------------------

	memset(password, 0x01, 32);
	memset(salt, 0x02, 16);
	memset(secret, 0x03, 8);
	memset(data, 0x04, 12);

	argon2d(password, 32, salt, 16, 4, 32, 3, secret, 8, data, 12, key, 32);
	status += CHECK_BLOCK(key, 32, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");

	// -------------------------------------------------------------------------------------------------------

	memset(password, 0x01, 32);
	memset(salt, 0x02, 16);
	memset(secret, 0x03, 8);
	memset(data, 0x04, 12);

	argon2i(password, 32, salt, 16, 4, 32, 3, secret, 8, data, 12, key, 32);
	status += CHECK_BLOCK(key, 32, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");

	// -------------------------------------------------------------------------------------------------------

	memset(password, 0x01, 32);
	memset(salt, 0x02, 16);
	memset(secret, 0x03, 8);
	memset(data, 0x04, 12);

	argon2id(password, 32, salt, 16, 4, 32, 3, secret, 8, data, 12, key, 32);
	status += CHECK_BLOCK(key, 32, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");

	// -------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return argon2_test_suite();
}
