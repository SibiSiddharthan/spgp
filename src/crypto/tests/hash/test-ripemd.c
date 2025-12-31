/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <ripemd.h>
#include <test.h>

int32_t ripemd160_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[RIPEMD160_HASH_SIZE];

	// See RIPEMD-160: A Strengthened Version of RIPEMD, Appendix B for test vectors.

	ripemd160_hash("", 0, buffer);
	status += CHECK_HASH(buffer, RIPEMD160_HASH_SIZE, "9c1185a5c5e9fc54612808977ee8f548b2258d31");

	// ----------------------------------------------------------------------------------------------------------------

	ripemd160_hash("a", 1, buffer);
	status += CHECK_HASH(buffer, RIPEMD160_HASH_SIZE, "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");

	// ----------------------------------------------------------------------------------------------------------------

	ripemd160_hash("abc", 3, buffer);
	status += CHECK_HASH(buffer, RIPEMD160_HASH_SIZE, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");

	// ----------------------------------------------------------------------------------------------------------------

	ripemd160_hash("message digest", 14, buffer);
	status += CHECK_HASH(buffer, RIPEMD160_HASH_SIZE, "5d0689ef49d2fae572b881b123a85ffa21595f36");

	// ----------------------------------------------------------------------------------------------------------------

	ripemd160_hash("abcdefghijklmnopqrstuvwxyz", 26, buffer);
	status += CHECK_HASH(buffer, RIPEMD160_HASH_SIZE, "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");

	// ----------------------------------------------------------------------------------------------------------------

	ripemd160_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, buffer);
	status += CHECK_HASH(buffer, RIPEMD160_HASH_SIZE, "12a053384a9c0c88e405a06c27dcf49ada62eb2b");

	// ----------------------------------------------------------------------------------------------------------------

	ripemd160_hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62, buffer);
	status += CHECK_HASH(buffer, RIPEMD160_HASH_SIZE, "b0e20b6e3116640286ed3a87a5713079b21f5189");

	// ----------------------------------------------------------------------------------------------------------------

	ripemd160_hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, buffer);
	status += CHECK_HASH(buffer, RIPEMD160_HASH_SIZE, "9b752e45573d4b39f4dbd3323cab82bf63326bfb");

	// ----------------------------------------------------------------------------------------------------------------

	ripemd160_ctx ctx = {0};

	ripemd160_init(&ctx);

	for (int32_t i = 0; i < 1000000; i += 50)
	{
		ripemd160_update(&ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 50);
	}

	ripemd160_final(&ctx, buffer);

	status += CHECK_HASH(buffer, RIPEMD160_HASH_SIZE, "52783243c1697bdbe16d37f97f68f08325dc1528");

	return status;
}

int main()
{
	return ripemd160_test_suite();
}
