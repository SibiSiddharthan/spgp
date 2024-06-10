/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <md5.h>

#include <test.h>

int32_t md5_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[MD5_HASH_SIZE];

	// See RFC 1321, Appendix A.5 for test vectors.

	md5_hash("", 0, buffer);
	status += CHECK_HASH(buffer, MD5_HASH_SIZE, "d41d8cd98f00b204e9800998ecf8427e");

	// ----------------------------------------------------------------------------------------------------------------

	md5_hash("a", 1, buffer);
	status += CHECK_HASH(buffer, MD5_HASH_SIZE, "0cc175b9c0f1b6a831c399e269772661");

	// ----------------------------------------------------------------------------------------------------------------

	md5_hash("abc", 3, buffer);
	status += CHECK_HASH(buffer, MD5_HASH_SIZE, "900150983cd24fb0d6963f7d28e17f72");

	// ----------------------------------------------------------------------------------------------------------------

	md5_hash("message digest", 14, buffer);
	status += CHECK_HASH(buffer, MD5_HASH_SIZE, "f96b697d7cb7938d525a2f31aaf161d0");

	// ----------------------------------------------------------------------------------------------------------------

	md5_hash("abcdefghijklmnopqrstuvwxyz", 26, buffer);
	status += CHECK_HASH(buffer, MD5_HASH_SIZE, "c3fcd3d76192e4007dfb496cca67e13b");

	// ----------------------------------------------------------------------------------------------------------------

	md5_hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62, buffer);
	status += CHECK_HASH(buffer, MD5_HASH_SIZE, "d174ab98d277d9f5a5611c2c9f419d9f");

	// ----------------------------------------------------------------------------------------------------------------

	md5_hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, buffer);
	status += CHECK_HASH(buffer, MD5_HASH_SIZE, "57edf4a22be3c955ac49da2e2107b67a");

	return status;
}

int main()
{
	return md5_test_suite();
}
