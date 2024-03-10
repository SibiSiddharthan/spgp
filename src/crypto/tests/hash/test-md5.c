/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <md5.h>

#define MD5_CHECK_SIZE 64

static char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static void hash_to_hex(byte_t hash[MD5_HASH_SIZE], char hex[MD5_CHECK_SIZE])
{
	int32_t i = 0, j = 0;

	for (i = 0; i < MD5_HASH_SIZE; ++i)
	{
		byte_t a, b;

		a = hash[i] / 16;
		b = hash[i] % 16;

		hex[j++] = hex_table[a];
		hex[j++] = hex_table[b];
	}
}

static int32_t check_hash(char *expected, char *actual)
{
	int32_t status;

	status = strcmp(expected, actual);

	if (status == 0)
	{
		return 0;
	}

	printf("MD5 Hash does not match.\nExpected: %s\nGot:      %s\n", expected, actual);

	return 1;
}

int32_t md5_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[MD5_HASH_SIZE];
	char check[MD5_CHECK_SIZE];

	// See RFC 1321, Appendix A.5 for test cases

	memset(buffer, 0, MD5_HASH_SIZE);
	memset(check, 0, MD5_CHECK_SIZE);

	md5_quick_hash("", 0, buffer);
	hash_to_hex(buffer, check);
	status += check_hash("d41d8cd98f00b204e9800998ecf8427e", check);

	// ----------------------------------------------------------------------------------------------------------------

	memset(buffer, 0, MD5_HASH_SIZE);
	memset(check, 0, MD5_CHECK_SIZE);

	md5_quick_hash("a", 1, buffer);
	hash_to_hex(buffer, check);
	status += check_hash("0cc175b9c0f1b6a831c399e269772661", check);

	// ----------------------------------------------------------------------------------------------------------------

	memset(buffer, 0, MD5_HASH_SIZE);
	memset(check, 0, MD5_CHECK_SIZE);

	md5_quick_hash("abc", 3, buffer);
	hash_to_hex(buffer, check);
	status += check_hash("900150983cd24fb0d6963f7d28e17f72", check);

	// ----------------------------------------------------------------------------------------------------------------

	memset(buffer, 0, MD5_HASH_SIZE);
	memset(check, 0, MD5_CHECK_SIZE);

	md5_quick_hash("message digest", 14, buffer);
	hash_to_hex(buffer, check);
	status += check_hash("f96b697d7cb7938d525a2f31aaf161d0", check);

	// ----------------------------------------------------------------------------------------------------------------

	memset(buffer, 0, MD5_HASH_SIZE);
	memset(check, 0, MD5_CHECK_SIZE);

	md5_quick_hash("abcdefghijklmnopqrstuvwxyz", 26, buffer);
	hash_to_hex(buffer, check);
	status += check_hash("c3fcd3d76192e4007dfb496cca67e13b", check);

	// ----------------------------------------------------------------------------------------------------------------

	memset(buffer, 0, MD5_HASH_SIZE);
	memset(check, 0, MD5_CHECK_SIZE);

	md5_quick_hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62, buffer);
	hash_to_hex(buffer, check);
	status += check_hash("d174ab98d277d9f5a5611c2c9f419d9f", check);

	// ----------------------------------------------------------------------------------------------------------------

	memset(buffer, 0, MD5_HASH_SIZE);
	memset(check, 0, MD5_CHECK_SIZE);

	md5_quick_hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, buffer);
	hash_to_hex(buffer, check);
	status += check_hash("57edf4a22be3c955ac49da2e2107b67a", check);

	return status;
}

int main()
{
	return md5_test_suite();
}
