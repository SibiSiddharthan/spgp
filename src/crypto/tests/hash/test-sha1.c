/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <sha.h>

#include <test.h>

int32_t sha1_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[SHA1_HASH_SIZE];

	// See https://www.di-mgt.com.au/sha_testvectors.html for SHA-1 test vectors.

	sha1_hash("", 0, buffer);
	status += CHECK_HASH(buffer, SHA1_HASH_SIZE, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

	// ----------------------------------------------------------------------------------------------------------------

	sha1_hash("abc", 3, buffer);
	status += CHECK_HASH(buffer, SHA1_HASH_SIZE, "a9993e364706816aba3e25717850c26c9cd0d89d");

	// ----------------------------------------------------------------------------------------------------------------

	sha1_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, buffer);
	status += CHECK_HASH(buffer, SHA1_HASH_SIZE, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");

	// ----------------------------------------------------------------------------------------------------------------

	sha1_hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
						 112, buffer);
	status += CHECK_HASH(buffer, SHA1_HASH_SIZE, "a49b2446a02c645bf419f995b67091253a04a259");

	// ----------------------------------------------------------------------------------------------------------------

	sha1_ctx *ctx = sha1_new();
	for (int32_t i = 0; i < 1000000; i += 50)
	{
		sha1_update(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 50);
	}
	sha1_final(ctx, buffer);
	sha1_delete(ctx);

	status += CHECK_HASH(buffer, SHA1_HASH_SIZE, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");

	return status;
}

int main()
{
	return sha1_test_suite();
}
