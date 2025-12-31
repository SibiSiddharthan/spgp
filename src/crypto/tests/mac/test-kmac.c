/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <kmac.h>
#include <test.h>

// Test vectors taken from NIST

int32_t kmac128_test_suite(void)
{
	int32_t status = 0;
	byte_t mac[256] = {0};
	byte_t input[256] = {0};
	byte_t key[256] = {0};

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 4, "00010203");
	kmac128(key, 32, NULL, 0, input, 4, mac, 32);

	status += CHECK_HASH(mac, 32, "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 4, "00010203");
	kmac128(key, 32, "My Tagged Application", 21, input, 4, mac, 32);

	status += CHECK_HASH(mac, 32, "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 200,
				 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3"
				 "c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778"
				 "797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b"
				 "5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
	kmac128(key, 32, "My Tagged Application", 21, input, 200, mac, 32);

	status += CHECK_HASH(mac, 32, "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230");

	// ----------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t kmacxof128_test_suite(void)
{
	int32_t status = 0;
	byte_t mac[256] = {0};
	byte_t input[256] = {0};
	byte_t key[256] = {0};

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 4, "00010203");
	kmacxof128(key, 32, NULL, 0, input, 4, mac, 32);

	status += CHECK_HASH(mac, 32, "cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 4, "00010203");
	kmacxof128(key, 32, "My Tagged Application", 21, input, 4, mac, 32);

	status += CHECK_HASH(mac, 32, "31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 200,
				 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3"
				 "c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778"
				 "797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b"
				 "5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
	kmacxof128(key, 32, "My Tagged Application", 21, input, 200, mac, 32);

	status += CHECK_HASH(mac, 32, "47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f");

	// ----------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t kmac256_test_suite(void)
{
	int32_t status = 0;
	byte_t mac[256] = {0};
	byte_t input[256] = {0};
	byte_t key[256] = {0};

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 4, "00010203");
	kmac256(key, 32, "My Tagged Application", 21, input, 4, mac, 64);

	status += CHECK_HASH(
		mac, 64,
		"20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 200,
				 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3"
				 "c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778"
				 "797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b"
				 "5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
	kmac256(key, 32, NULL, 0, input, 200, mac, 64);

	status += CHECK_HASH(
		mac, 64,
		"75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 200,
				 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3"
				 "c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778"
				 "797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b"
				 "5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
	kmac256(key, 32, "My Tagged Application", 21, input, 200, mac, 64);

	status += CHECK_HASH(
		mac, 64,
		"b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965");

	return status;
}

int32_t kmacxof256_test_suite(void)
{
	int32_t status = 0;
	byte_t mac[256] = {0};
	byte_t input[256] = {0};
	byte_t key[256] = {0};

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 4, "00010203");
	kmacxof256(key, 32, "My Tagged Application", 21, input, 4, mac, 64);

	status += CHECK_HASH(
		mac, 64,
		"1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa96faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 200,
				 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3"
				 "c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778"
				 "797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b"
				 "5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
	kmacxof256(key, 32, NULL, 0, input, 200, mac, 64);

	status += CHECK_HASH(
		mac, 64,
		"ff7b171f1e8a2b24683eed37830ee797538ba8dc563f6da1e667391a75edc02ca633079f81ce12a25f45615ec89972031d18337331d24ceb8f8ca8e6a19fd98b");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
	hex_to_block(input, 200,
				 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3"
				 "c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778"
				 "797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b"
				 "5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
	kmacxof256(key, 32, "My Tagged Application", 21, input, 200, mac, 64);

	status += CHECK_HASH(
		mac, 64,
		"d5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d");

	return status;

	// ----------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return kmac128_test_suite() + kmacxof128_test_suite() + kmac256_test_suite() + kmacxof256_test_suite();
}
