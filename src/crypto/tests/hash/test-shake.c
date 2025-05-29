/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <shake.h>

#include <test.h>

// Test vectors taken from NIST

int32_t shake128_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[128] = {0};
	byte_t input[128] = {0};

	// ----------------------------------------------------------------------------------------------------------------

	shake128_xof("", 0, buffer, 16);
	status += CHECK_HASH(buffer, 16, "7f9c2ba4e88f827d616045507605853e");

	// ----------------------------------------------------------------------------------------------------------------

	shake128_xof("abc", 3, buffer, 16);
	status += CHECK_HASH(buffer, 16, "5881092dd818bf5cf8a3ddb793fbcba7");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(input, 16, "35f05940542b20c76f0d26f0826d78e7");
	shake128_xof(input, 16, buffer, 32);
	status += CHECK_HASH(buffer, 32, "ea14fce8784800d1153d46273b377ad7e2ecd69c0203ae508dffe5cf6d5226fa");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(input, 16, "25ad5706a2c0c12189a77ddebf01b984");
	shake128_xof(input, 16, buffer, 56);
	status += CHECK_HASH(
		buffer, 56, "70133db4c8ff3655393b0537cb8d414ce9c59f114e338cdeb708d264b2572f900492f5e96e3ee79a0b2bea422ef47e2e6afa7ca093e2754a");

	return status;
}

int32_t shake256_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[256] = {0};
	byte_t input[128] = {0};

	// ----------------------------------------------------------------------------------------------------------------

	shake256_xof("", 0, buffer, 32);
	status += CHECK_HASH(buffer, 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");

	// ----------------------------------------------------------------------------------------------------------------

	shake256_xof("abc", 3, buffer, 32);
	status += CHECK_HASH(buffer, 32, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(input, 32, "c61a9188812ae73994bc0d6d4021e31bf124dc72669749111232da7ac29e61c4");
	shake256_xof(input, 32, buffer, 2);
	status += CHECK_HASH(buffer, 2, "23ce");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(input, 32, "6ae23f058f0f2264a18cd609acc26dd4dbc00f5c3ee9e13ecaea2bb5a2f0bb6b");
	shake256_xof(input, 32, buffer, 160);
	status += CHECK_HASH(buffer, 160,
						 "b9b92544fb25cfe4ec6fe437d8da2bbe00f7bdaface3de97b8775a44d753c3adca3f7c6f183cc8647e229070439aa9539ae1f8f13470c9d35"
						 "27fffdeef6c94f9f0520ff0c1ba8b16e16014e1af43ac6d94cb7929188cce9d7b02f81a2746f52ba16988e5f6d93298d778dfe05ea0ef256a"
						 "e3728643ce3e29c794a0370e9ca6a8bf3e7a41e86770676ac106f7ae79e67027ce7b7b38efe27d253a52b5cb54d6eb");

	return status;
}

int32_t cshake128_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[256] = {0};
	byte_t input[256] = {0};

	shake128_ctx sctx;

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(input, 4, "00010203");

	cshake128_init(&sctx, 256, NULL, 0, "Email Signature", 15);
	cshake128_update(&sctx, input, 4);
	cshake128_final(&sctx, buffer, 128);

	status += CHECK_HASH(buffer, 32, "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(input, 200,
				 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3"
				 "c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778"
				 "797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b"
				 "5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");

	cshake128_init(&sctx, 256, NULL, 0, "Email Signature", 15);
	cshake128_update(&sctx, input, 200);
	cshake128_final(&sctx, buffer, 128);

	status += CHECK_HASH(buffer, 32, "c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b");

	return status;
}

int32_t cshake256_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[256] = {0};
	byte_t input[256] = {0};

	shake256_ctx sctx;

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(input, 4, "00010203");

	cshake256_init(&sctx, 512, NULL, 0, "Email Signature", 15);
	cshake256_update(&sctx, input, 4);
	cshake256_final(&sctx, buffer, 128);

	status += CHECK_HASH(
		buffer, 64,
		"d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(input, 200,
				 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3"
				 "c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778"
				 "797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b"
				 "5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");

	cshake256_init(&sctx, 512, NULL, 0, "Email Signature", 15);
	cshake256_update(&sctx, input, 200);
	cshake256_final(&sctx, buffer, 128);

	status += CHECK_HASH(
		buffer, 64,
		"07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb");

	return status;
}

int main()
{
	return shake128_test_suite() + shake256_test_suite() + cshake128_test_suite() + cshake256_test_suite();
}
