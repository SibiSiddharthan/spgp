/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>

#include <hmac.h>
#include <md5.h>
#include <ripemd.h>
#include <sha.h>

#include <test.h>

// RFC 2202 : Test Cases for HMAC-MD5 and HMAC-SHA-1
// RFC 2286 : Test Cases for HMAC-RIPEMD160 and HMAC-RIPEMD128
// RFC 4231 : Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512

int32_t hmac_md5_test_suite(void)
{
	int32_t status = 0;

	size_t key_size = 0;
	byte_t key[128];
	byte_t data[128];
	byte_t mac[MD5_HASH_SIZE];

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, MD5_HASH_SIZE);

	key_size = 16;
	hex_to_block(key, key_size, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
	hmac_md5(key, key_size, "Hi There", 8, mac, MD5_HASH_SIZE);

	status += CHECK_MAC(mac, MD5_HASH_SIZE, "9294727a3638bb1c13f48ef8158bfc9d");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, MD5_HASH_SIZE);

	key_size = 4;
	hex_to_block(key, key_size, "4a656665"); // "Jefe"
	hmac_md5(key, key_size, "what do ya want for nothing?", 28, mac, MD5_HASH_SIZE);

	status += CHECK_MAC(mac, MD5_HASH_SIZE, "750c783e6ab0b503eaa86e310a5db738");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, MD5_HASH_SIZE);
	memset(data, 0xdd, 50);

	key_size = 16;
	hex_to_block(key, key_size, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	hmac_md5(key, key_size, data, 50, mac, MD5_HASH_SIZE);

	status += CHECK_MAC(mac, MD5_HASH_SIZE, "56be34521d144c88dbb8c733f0e8b3f6");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, MD5_HASH_SIZE);
	memset(data, 0xcd, 50);

	key_size = 25;
	hex_to_block(key, key_size, "0102030405060708090a0b0c0d0e0f10111213141516171819");
	hmac_md5(key, key_size, data, 50, mac, MD5_HASH_SIZE);

	status += CHECK_MAC(mac, MD5_HASH_SIZE, "697eaf0aca3a3aea3a75164746ffaa79");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, MD5_HASH_SIZE);

	key_size = 16;
	hex_to_block(key, key_size, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
	hmac_md5(key, key_size, "Test With Truncation", 20, mac, 12);

	status += CHECK_MAC(mac, 12, "56461ef2342edc00f9bab995");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, MD5_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_md5(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac, MD5_HASH_SIZE);

	status += CHECK_MAC(mac, MD5_HASH_SIZE, "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, MD5_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_md5(key, key_size, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73, mac, MD5_HASH_SIZE);

	status += CHECK_MAC(mac, MD5_HASH_SIZE, "6f630fad67cda0ee1fb1f562db3aa53e");

	return status;
}

int32_t hmac_ripemd160_test_suite(void)
{
	int32_t status = 0;

	size_t key_size = 0;
	byte_t key[128];
	byte_t data[128];
	byte_t mac[RIPEMD160_HASH_SIZE];

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, RIPEMD160_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
	hmac_ripemd160(key, key_size, "Hi There", 8, mac, RIPEMD160_HASH_SIZE);

	status += CHECK_MAC(mac, RIPEMD160_HASH_SIZE, "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, RIPEMD160_HASH_SIZE);

	key_size = 4;
	hex_to_block(key, key_size, "4a656665"); // "Jefe"
	hmac_ripemd160(key, key_size, "what do ya want for nothing?", 28, mac, RIPEMD160_HASH_SIZE);

	status += CHECK_MAC(mac, RIPEMD160_HASH_SIZE, "dda6c0213a485a9e24f4742064a7f033b43c4069");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, RIPEMD160_HASH_SIZE);
	memset(data, 0xdd, 50);

	key_size = 20;
	hex_to_block(key, key_size, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	hmac_ripemd160(key, key_size, data, 50, mac, RIPEMD160_HASH_SIZE);

	status += CHECK_MAC(mac, RIPEMD160_HASH_SIZE, "b0b105360de759960ab4f35298e116e295d8e7c1");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, RIPEMD160_HASH_SIZE);
	memset(data, 0xcd, 50);

	key_size = 25;
	hex_to_block(key, key_size, "0102030405060708090a0b0c0d0e0f10111213141516171819");
	hmac_ripemd160(key, key_size, data, 50, mac, RIPEMD160_HASH_SIZE);

	status += CHECK_MAC(mac, RIPEMD160_HASH_SIZE, "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, RIPEMD160_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
	hmac_ripemd160(key, key_size, "Test With Truncation", 20, mac, 12);

	status += CHECK_MAC(mac, 12, "7619693978f91d90539ae786");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, RIPEMD160_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_ripemd160(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac, RIPEMD160_HASH_SIZE);

	status += CHECK_MAC(mac, RIPEMD160_HASH_SIZE, "6466ca07ac5eac29e1bd523e5ada7605b791fd8b");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, RIPEMD160_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_ripemd160(key, key_size, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73, mac,
				   RIPEMD160_HASH_SIZE);

	status += CHECK_MAC(mac, RIPEMD160_HASH_SIZE, "69ea60798d71616cce5fd0871e23754cd75d5a0a");

	return status;
}

int32_t hmac_sha1_test_suite(void)
{
	int32_t status = 0;

	size_t key_size = 0;
	byte_t key[128];
	byte_t data[128];
	byte_t mac[SHA1_HASH_SIZE];

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, SHA1_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
	hmac_sha1(key, key_size, "Hi There", 8, mac, SHA1_HASH_SIZE);

	status += CHECK_MAC(mac, SHA1_HASH_SIZE, "b617318655057264e28bc0b6fb378c8ef146be00");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, SHA1_HASH_SIZE);

	key_size = 4;
	hex_to_block(key, key_size, "4a656665"); // "Jefe"
	hmac_sha1(key, key_size, "what do ya want for nothing?", 28, mac, SHA1_HASH_SIZE);

	status += CHECK_MAC(mac, SHA1_HASH_SIZE, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, SHA1_HASH_SIZE);
	memset(data, 0xdd, 50);

	key_size = 20;
	hex_to_block(key, key_size, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	hmac_sha1(key, key_size, data, 50, mac, SHA1_HASH_SIZE);

	status += CHECK_MAC(mac, SHA1_HASH_SIZE, "125d7342b9ac11cd91a39af48aa17b4f63f175d3");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, SHA1_HASH_SIZE);
	memset(data, 0xcd, 50);

	key_size = 25;
	hex_to_block(key, key_size, "0102030405060708090a0b0c0d0e0f10111213141516171819");
	hmac_sha1(key, key_size, data, 50, mac, SHA1_HASH_SIZE);

	status += CHECK_MAC(mac, SHA1_HASH_SIZE, "4c9007f4026250c6bc8414f9bf50c86c2d7235da");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, SHA1_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
	hmac_sha1(key, key_size, "Test With Truncation", 20, mac, 12);

	status += CHECK_MAC(mac, 12, "4c1a03424b55e07fe7f27be1");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, SHA1_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_sha1(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac, SHA1_HASH_SIZE);

	status += CHECK_MAC(mac, SHA1_HASH_SIZE, "aa4ae5e15272d00e95705637ce8a3b55ed402112");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, SHA1_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_sha1(key, key_size, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73, mac, SHA1_HASH_SIZE);

	status += CHECK_MAC(mac, SHA1_HASH_SIZE, "e8e99d0f45237d786d6bbaa7965c7808bbff1a91");

	return status;
}

int32_t hmac_sha2_test_suite(void)
{
	int32_t status = 0;

	size_t key_size = 0;
	byte_t key[256];
	byte_t data[256];
	byte_t mac_sha224[SHA224_HASH_SIZE];
	byte_t mac_sha256[SHA256_HASH_SIZE];
	byte_t mac_sha384[SHA384_HASH_SIZE];
	byte_t mac_sha512[SHA512_HASH_SIZE];

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha224, 0, SHA224_HASH_SIZE);
	memset(mac_sha256, 0, SHA256_HASH_SIZE);
	memset(mac_sha384, 0, SHA384_HASH_SIZE);
	memset(mac_sha512, 0, SHA512_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

	hmac_sha224(key, key_size, "Hi There", 8, mac_sha224, SHA224_HASH_SIZE);
	hmac_sha256(key, key_size, "Hi There", 8, mac_sha256, SHA256_HASH_SIZE);
	hmac_sha384(key, key_size, "Hi There", 8, mac_sha384, SHA384_HASH_SIZE);
	hmac_sha512(key, key_size, "Hi There", 8, mac_sha512, SHA512_HASH_SIZE);

	status += CHECK_MAC(mac_sha224, SHA224_HASH_SIZE, "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
	status += CHECK_MAC(mac_sha256, SHA256_HASH_SIZE, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	status += CHECK_MAC(mac_sha384, SHA384_HASH_SIZE,
						"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
	status += CHECK_MAC(
		mac_sha512, SHA512_HASH_SIZE,
		"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha224, 0, SHA224_HASH_SIZE);
	memset(mac_sha256, 0, SHA256_HASH_SIZE);
	memset(mac_sha384, 0, SHA384_HASH_SIZE);
	memset(mac_sha512, 0, SHA512_HASH_SIZE);

	key_size = 4;
	hex_to_block(key, key_size, "4a656665"); // "Jefe"

	hmac_sha224(key, key_size, "what do ya want for nothing?", 28, mac_sha224, SHA224_HASH_SIZE);
	hmac_sha256(key, key_size, "what do ya want for nothing?", 28, mac_sha256, SHA256_HASH_SIZE);
	hmac_sha384(key, key_size, "what do ya want for nothing?", 28, mac_sha384, SHA384_HASH_SIZE);
	hmac_sha512(key, key_size, "what do ya want for nothing?", 28, mac_sha512, SHA512_HASH_SIZE);

	status += CHECK_MAC(mac_sha224, SHA224_HASH_SIZE, "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44");
	status += CHECK_MAC(mac_sha256, SHA256_HASH_SIZE, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	status += CHECK_MAC(mac_sha384, SHA384_HASH_SIZE,
						"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
	status += CHECK_MAC(
		mac_sha512, SHA512_HASH_SIZE,
		"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(data, 0xdd, 50);
	memset(mac_sha224, 0, SHA224_HASH_SIZE);
	memset(mac_sha256, 0, SHA256_HASH_SIZE);
	memset(mac_sha384, 0, SHA384_HASH_SIZE);
	memset(mac_sha512, 0, SHA512_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

	hmac_sha224(key, key_size, data, 50, mac_sha224, SHA224_HASH_SIZE);
	hmac_sha256(key, key_size, data, 50, mac_sha256, SHA256_HASH_SIZE);
	hmac_sha384(key, key_size, data, 50, mac_sha384, SHA384_HASH_SIZE);
	hmac_sha512(key, key_size, data, 50, mac_sha512, SHA512_HASH_SIZE);

	status += CHECK_MAC(mac_sha224, SHA224_HASH_SIZE, "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea");
	status += CHECK_MAC(mac_sha256, SHA256_HASH_SIZE, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
	status += CHECK_MAC(mac_sha384, SHA384_HASH_SIZE,
						"88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27");
	status += CHECK_MAC(
		mac_sha512, SHA512_HASH_SIZE,
		"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(data, 0xcd, 50);
	memset(mac_sha224, 0, SHA224_HASH_SIZE);
	memset(mac_sha256, 0, SHA256_HASH_SIZE);
	memset(mac_sha384, 0, SHA384_HASH_SIZE);
	memset(mac_sha512, 0, SHA512_HASH_SIZE);

	key_size = 25;
	hex_to_block(key, key_size, "0102030405060708090a0b0c0d0e0f10111213141516171819");

	hmac_sha224(key, key_size, data, 50, mac_sha224, SHA224_HASH_SIZE);
	hmac_sha256(key, key_size, data, 50, mac_sha256, SHA256_HASH_SIZE);
	hmac_sha384(key, key_size, data, 50, mac_sha384, SHA384_HASH_SIZE);
	hmac_sha512(key, key_size, data, 50, mac_sha512, SHA512_HASH_SIZE);

	status += CHECK_MAC(mac_sha224, SHA224_HASH_SIZE, "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a");
	status += CHECK_MAC(mac_sha256, SHA256_HASH_SIZE, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
	status += CHECK_MAC(mac_sha384, SHA384_HASH_SIZE,
						"3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb");
	status += CHECK_MAC(
		mac_sha512, SHA512_HASH_SIZE,
		"b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha224, 0, SHA224_HASH_SIZE);
	memset(mac_sha256, 0, SHA256_HASH_SIZE);
	memset(mac_sha384, 0, SHA384_HASH_SIZE);
	memset(mac_sha512, 0, SHA512_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");

	hmac_sha224(key, key_size, "Test With Truncation", 20, mac_sha224, 16);
	hmac_sha256(key, key_size, "Test With Truncation", 20, mac_sha256, 16);
	hmac_sha384(key, key_size, "Test With Truncation", 20, mac_sha384, 16);
	hmac_sha512(key, key_size, "Test With Truncation", 20, mac_sha512, 16);

	status += CHECK_MAC(mac_sha224, 16, "0e2aea68a90c8d37c988bcdb9fca6fa8");
	status += CHECK_MAC(mac_sha256, 16, "a3b6167473100ee06e0c796c2955552b");
	status += CHECK_MAC(mac_sha384, 16, "3abf34c3503b2a23a46efc619baef897");
	status += CHECK_MAC(mac_sha512, 16, "415fad6271580a531d4179bc891d87a6");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha224, 0, SHA224_HASH_SIZE);
	memset(mac_sha256, 0, SHA256_HASH_SIZE);
	memset(mac_sha384, 0, SHA384_HASH_SIZE);
	memset(mac_sha512, 0, SHA512_HASH_SIZE);

	key_size = 131;
	memset(key, 0xaa, key_size);

	hmac_sha224(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha224, SHA224_HASH_SIZE);
	hmac_sha256(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha256, SHA256_HASH_SIZE);
	hmac_sha384(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha384, SHA384_HASH_SIZE);
	hmac_sha512(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha512, SHA512_HASH_SIZE);

	status += CHECK_MAC(mac_sha224, SHA224_HASH_SIZE, "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e");
	status += CHECK_MAC(mac_sha256, SHA256_HASH_SIZE, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
	status += CHECK_MAC(mac_sha384, SHA384_HASH_SIZE,
						"4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952");
	status += CHECK_MAC(
		mac_sha512, SHA512_HASH_SIZE,
		"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha224, 0, SHA224_HASH_SIZE);
	memset(mac_sha256, 0, SHA256_HASH_SIZE);
	memset(mac_sha384, 0, SHA384_HASH_SIZE);
	memset(mac_sha512, 0, SHA512_HASH_SIZE);

	key_size = 131;
	memset(key, 0xaa, key_size);

	hmac_sha224(key, key_size,
				"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				"being used by the HMAC algorithm.",
				152, mac_sha224, SHA224_HASH_SIZE);
	hmac_sha256(key, key_size,
				"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				"being used by the HMAC algorithm.",
				152, mac_sha256, SHA256_HASH_SIZE);
	hmac_sha384(key, key_size,
				"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				"being used by the HMAC algorithm.",
				152, mac_sha384, SHA384_HASH_SIZE);
	hmac_sha512(key, key_size,
				"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				"being used by the HMAC algorithm.",
				152, mac_sha512, SHA512_HASH_SIZE);

	status += CHECK_MAC(mac_sha224, SHA224_HASH_SIZE, "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1");
	status += CHECK_MAC(mac_sha256, SHA256_HASH_SIZE, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
	status += CHECK_MAC(mac_sha384, SHA384_HASH_SIZE,
						"6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e");
	status += CHECK_MAC(
		mac_sha512, SHA512_HASH_SIZE,
		"e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");

	return status;
}

int32_t hmac_sha3_test_suite(void)
{
	int32_t status = 0;

	size_t key_size = 0;
	byte_t key[256];
	byte_t data[256];
	byte_t mac_sha3_224[SHA3_224_HASH_SIZE];
	byte_t mac_sha3_256[SHA3_256_HASH_SIZE];
	byte_t mac_sha3_384[SHA3_384_HASH_SIZE];
	byte_t mac_sha3_512[SHA3_512_HASH_SIZE];

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha3_224, 0, SHA3_224_HASH_SIZE);
	memset(mac_sha3_256, 0, SHA3_256_HASH_SIZE);
	memset(mac_sha3_384, 0, SHA3_384_HASH_SIZE);
	memset(mac_sha3_512, 0, SHA3_512_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

	hmac_sha3_224(key, key_size, "Hi There", 8, mac_sha3_224, SHA3_224_HASH_SIZE);
	hmac_sha3_256(key, key_size, "Hi There", 8, mac_sha3_256, SHA3_256_HASH_SIZE);
	hmac_sha3_384(key, key_size, "Hi There", 8, mac_sha3_384, SHA3_384_HASH_SIZE);
	hmac_sha3_512(key, key_size, "Hi There", 8, mac_sha3_512, SHA3_512_HASH_SIZE);

	status += CHECK_MAC(mac_sha3_224, SHA3_224_HASH_SIZE, "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7");
	status += CHECK_MAC(mac_sha3_256, SHA3_256_HASH_SIZE, "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb");
	status += CHECK_MAC(mac_sha3_384, SHA3_384_HASH_SIZE,
						"68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd");
	status += CHECK_MAC(
		mac_sha3_512, SHA3_512_HASH_SIZE,
		"eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha3_224, 0, SHA3_224_HASH_SIZE);
	memset(mac_sha3_256, 0, SHA3_256_HASH_SIZE);
	memset(mac_sha3_384, 0, SHA3_384_HASH_SIZE);
	memset(mac_sha3_512, 0, SHA3_512_HASH_SIZE);

	key_size = 4;
	hex_to_block(key, key_size, "4a656665"); // "Jefe"

	hmac_sha3_224(key, key_size, "what do ya want for nothing?", 28, mac_sha3_224, SHA3_224_HASH_SIZE);
	hmac_sha3_256(key, key_size, "what do ya want for nothing?", 28, mac_sha3_256, SHA3_256_HASH_SIZE);
	hmac_sha3_384(key, key_size, "what do ya want for nothing?", 28, mac_sha3_384, SHA3_384_HASH_SIZE);
	hmac_sha3_512(key, key_size, "what do ya want for nothing?", 28, mac_sha3_512, SHA3_512_HASH_SIZE);

	status += CHECK_MAC(mac_sha3_224, SHA3_224_HASH_SIZE, "7fdb8dd88bd2f60d1b798634ad386811c2cfc85bfaf5d52bbace5e66");
	status += CHECK_MAC(mac_sha3_256, SHA3_256_HASH_SIZE, "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5");
	status += CHECK_MAC(mac_sha3_384, SHA3_384_HASH_SIZE,
						"f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a23ca13508a93243ce48c045dc007f26a21b3f5e0e9df4c20a");
	status += CHECK_MAC(
		mac_sha3_512, SHA3_512_HASH_SIZE,
		"5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(data, 0xdd, 50);
	memset(mac_sha3_224, 0, SHA3_224_HASH_SIZE);
	memset(mac_sha3_256, 0, SHA3_256_HASH_SIZE);
	memset(mac_sha3_384, 0, SHA3_384_HASH_SIZE);
	memset(mac_sha3_512, 0, SHA3_512_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

	hmac_sha3_224(key, key_size, data, 50, mac_sha3_224, SHA3_224_HASH_SIZE);
	hmac_sha3_256(key, key_size, data, 50, mac_sha3_256, SHA3_256_HASH_SIZE);
	hmac_sha3_384(key, key_size, data, 50, mac_sha3_384, SHA3_384_HASH_SIZE);
	hmac_sha3_512(key, key_size, data, 50, mac_sha3_512, SHA3_512_HASH_SIZE);

	status += CHECK_MAC(mac_sha3_224, SHA3_224_HASH_SIZE, "676cfc7d16153638780390692be142d2df7ce924b909c0c08dbfdc1a");
	status += CHECK_MAC(mac_sha3_256, SHA3_256_HASH_SIZE, "84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207");
	status += CHECK_MAC(mac_sha3_384, SHA3_384_HASH_SIZE,
						"275cd0e661bb8b151c64d288f1f782fb91a8abd56858d72babb2d476f0458373b41b6ab5bf174bec422e53fc3135ac6e");
	status += CHECK_MAC(
		mac_sha3_512, SHA3_512_HASH_SIZE,
		"309e99f9ec075ec6c6d475eda1180687fcf1531195802a99b5677449a8625182851cb332afb6a89c411325fbcbcd42afcb7b6e5aab7ea42c660f97fd8584bf03");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(data, 0xcd, 50);
	memset(mac_sha3_224, 0, SHA3_224_HASH_SIZE);
	memset(mac_sha3_256, 0, SHA3_256_HASH_SIZE);
	memset(mac_sha3_384, 0, SHA3_384_HASH_SIZE);
	memset(mac_sha3_512, 0, SHA3_512_HASH_SIZE);

	key_size = 25;
	hex_to_block(key, key_size, "0102030405060708090a0b0c0d0e0f10111213141516171819");

	hmac_sha3_224(key, key_size, data, 50, mac_sha3_224, SHA3_224_HASH_SIZE);
	hmac_sha3_256(key, key_size, data, 50, mac_sha3_256, SHA3_256_HASH_SIZE);
	hmac_sha3_384(key, key_size, data, 50, mac_sha3_384, SHA3_384_HASH_SIZE);
	hmac_sha3_512(key, key_size, data, 50, mac_sha3_512, SHA3_512_HASH_SIZE);

	status += CHECK_MAC(mac_sha3_224, SHA3_224_HASH_SIZE, "a9d7685a19c4e0dbd9df2556cc8a7d2a7733b67625ce594c78270eeb");
	status += CHECK_MAC(mac_sha3_256, SHA3_256_HASH_SIZE, "57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7");
	status += CHECK_MAC(mac_sha3_384, SHA3_384_HASH_SIZE,
						"3a5d7a879702c086bc96d1dd8aa15d9c46446b95521311c606fdc4e308f4b984da2d0f9449b3ba8425ec7fb8c31bc136");
	status += CHECK_MAC(
		mac_sha3_512, SHA3_512_HASH_SIZE,
		"b27eab1d6e8d87461c29f7f5739dd58e98aa35f8e823ad38c5492a2088fa0281993bbfff9a0e9c6bf121ae9ec9bb09d84a5ebac817182ea974673fb133ca0d1d");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha3_224, 0, SHA3_224_HASH_SIZE);
	memset(mac_sha3_256, 0, SHA3_256_HASH_SIZE);
	memset(mac_sha3_384, 0, SHA3_384_HASH_SIZE);
	memset(mac_sha3_512, 0, SHA3_512_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");

	hmac_sha3_224(key, key_size, "Test With Truncation", 20, mac_sha3_224, 16);
	hmac_sha3_256(key, key_size, "Test With Truncation", 20, mac_sha3_256, 16);
	hmac_sha3_384(key, key_size, "Test With Truncation", 20, mac_sha3_384, 16);
	hmac_sha3_512(key, key_size, "Test With Truncation", 20, mac_sha3_512, 16);

	status += CHECK_MAC(mac_sha3_224, 16, "49fdd3abd005ebb8ae63fea946d1883c");
	status += CHECK_MAC(mac_sha3_256, 16, "6e02c64537fb118057abb7fb66a23b3c");
	status += CHECK_MAC(mac_sha3_384, 16, "47c51ace1ffacffd7494724682615783");
	status += CHECK_MAC(mac_sha3_512, 16, "0fa7475948f43f48ca0516671e18978c");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha3_224, 0, SHA3_224_HASH_SIZE);
	memset(mac_sha3_256, 0, SHA3_256_HASH_SIZE);
	memset(mac_sha3_384, 0, SHA3_384_HASH_SIZE);
	memset(mac_sha3_512, 0, SHA3_512_HASH_SIZE);

	key_size = 131;
	memset(key, 0xaa, key_size);

	hmac_sha3_224(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha3_224, SHA3_224_HASH_SIZE);
	hmac_sha3_256(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha3_256, SHA3_256_HASH_SIZE);
	hmac_sha3_384(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha3_384, SHA3_384_HASH_SIZE);
	hmac_sha3_512(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha3_512, SHA3_512_HASH_SIZE);

	status += CHECK_MAC(mac_sha3_224, SHA3_224_HASH_SIZE, "b4a1f04c00287a9b7f6075b313d279b833bc8f75124352d05fb9995f");
	status += CHECK_MAC(mac_sha3_256, SHA3_256_HASH_SIZE, "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b");
	status += CHECK_MAC(mac_sha3_384, SHA3_384_HASH_SIZE,
						"0fc19513bf6bd878037016706a0e57bc528139836b9a42c3d419e498e0e1fb9616fd669138d33a1105e07c72b6953bcc");
	status += CHECK_MAC(
		mac_sha3_512, SHA3_512_HASH_SIZE,
		"00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839ac79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha3_224, 0, SHA3_224_HASH_SIZE);
	memset(mac_sha3_256, 0, SHA3_256_HASH_SIZE);
	memset(mac_sha3_384, 0, SHA3_384_HASH_SIZE);
	memset(mac_sha3_512, 0, SHA3_512_HASH_SIZE);

	key_size = 147;
	memset(key, 0xaa, key_size);

	hmac_sha3_224(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha3_224, SHA3_224_HASH_SIZE);
	hmac_sha3_256(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha3_256, SHA3_256_HASH_SIZE);
	hmac_sha3_384(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha3_384, SHA3_384_HASH_SIZE);
	hmac_sha3_512(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac_sha3_512, SHA3_512_HASH_SIZE);

	status += CHECK_MAC(mac_sha3_224, SHA3_224_HASH_SIZE, "b96d730c148c2daad8649d83defaa3719738d34775397b7571c38515");
	status += CHECK_MAC(mac_sha3_256, SHA3_256_HASH_SIZE, "a6072f86de52b38bb349fe84cd6d97fb6a37c4c0f62aae93981193a7229d3467");
	status += CHECK_MAC(mac_sha3_384, SHA3_384_HASH_SIZE,
						"713dff0302c85086ec5ad0768dd65a13ddd79068d8d4c6212b712e41649449111480230044185a99103ed82004ddbfcc");
	status += CHECK_MAC(
		mac_sha3_512, SHA3_512_HASH_SIZE,
		"b14835c819a290efb010ace6d8568dc6b84de60bc49b004c3b13eda763589451e5dd74292884d1bdce64e6b919dd61dc9c56a282a81c0bd14f1f365b49b83a5b");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha3_224, 0, SHA3_224_HASH_SIZE);
	memset(mac_sha3_256, 0, SHA3_256_HASH_SIZE);
	memset(mac_sha3_384, 0, SHA3_384_HASH_SIZE);
	memset(mac_sha3_512, 0, SHA3_512_HASH_SIZE);

	key_size = 131;
	memset(key, 0xaa, key_size);

	hmac_sha3_224(key, key_size,
				  "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				  "being used by the HMAC algorithm.",
				  152, mac_sha3_224, SHA3_224_HASH_SIZE);
	hmac_sha3_256(key, key_size,
				  "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				  "being used by the HMAC algorithm.",
				  152, mac_sha3_256, SHA3_256_HASH_SIZE);
	hmac_sha3_384(key, key_size,
				  "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				  "being used by the HMAC algorithm.",
				  152, mac_sha3_384, SHA3_384_HASH_SIZE);
	hmac_sha3_512(key, key_size,
				  "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				  "being used by the HMAC algorithm.",
				  152, mac_sha3_512, SHA3_512_HASH_SIZE);

	status += CHECK_MAC(mac_sha3_224, SHA3_224_HASH_SIZE, "05d8cd6d00faea8d1eb68ade28730bbd3cbab6929f0a086b29cd62a0");
	status += CHECK_MAC(mac_sha3_256, SHA3_256_HASH_SIZE, "65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123");
	status += CHECK_MAC(mac_sha3_384, SHA3_384_HASH_SIZE,
						"026fdf6b50741e373899c9f7d5406d4eb09fc6665636fc1a530029ddf5cf3ca5a900edce01f5f61e2f408cdf2fd3e7e8");
	status += CHECK_MAC(
		mac_sha3_512, SHA3_512_HASH_SIZE,
		"38a456a004bd10d32c9ab8336684112862c3db61adcca31829355eaf46fd5c73d06a1f0d13fec9a652fb3811b577b1b1d1b9789f97ae5b83c6f44dfcf1d67eba");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 256);
	memset(mac_sha3_224, 0, SHA3_224_HASH_SIZE);
	memset(mac_sha3_256, 0, SHA3_256_HASH_SIZE);
	memset(mac_sha3_384, 0, SHA3_384_HASH_SIZE);
	memset(mac_sha3_512, 0, SHA3_512_HASH_SIZE);

	key_size = 147;
	memset(key, 0xaa, key_size);

	hmac_sha3_224(key, key_size,
				  "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				  "being used by the HMAC algorithm.",
				  152, mac_sha3_224, SHA3_224_HASH_SIZE);
	hmac_sha3_256(key, key_size,
				  "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				  "being used by the HMAC algorithm.",
				  152, mac_sha3_256, SHA3_256_HASH_SIZE);
	hmac_sha3_384(key, key_size,
				  "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				  "being used by the HMAC algorithm.",
				  152, mac_sha3_384, SHA3_384_HASH_SIZE);
	hmac_sha3_512(key, key_size,
				  "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before "
				  "being used by the HMAC algorithm.",
				  152, mac_sha3_512, SHA3_512_HASH_SIZE);

	status += CHECK_MAC(mac_sha3_224, SHA3_224_HASH_SIZE, "c79c9b093424e588a9878bbcb089e018270096e9b4b1a9e8220c866a");
	status += CHECK_MAC(mac_sha3_256, SHA3_256_HASH_SIZE, "e6a36d9b915f86a093cac7d110e9e04cf1d6100d30475509c2475f571b758b5a");
	status += CHECK_MAC(mac_sha3_384, SHA3_384_HASH_SIZE,
						"cad18a8ff6c4cc3ad487b95f9769e9b61c062aefd6952569e6e6421897054cfc70b5fdc6605c18457112fc6aaad45585");
	status += CHECK_MAC(
		mac_sha3_512, SHA3_512_HASH_SIZE,
		"dc030ee7887034f32cf402df34622f311f3e6cf04860c6bbd7fa488674782b4659fdbdf3fd877852885cfe6e22185fe7b2ee952043629bc9d5f3298a41d02c66");

	return status;
}

int main()
{
	return hmac_md5_test_suite() + hmac_ripemd160_test_suite() + hmac_sha1_test_suite() + hmac_sha2_test_suite() + hmac_sha3_test_suite();
}
