/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>

#include <hmac.h>
#include <md5.h>
#include <ripemd.h>
#include <sha.h>

#include "test.h"

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

	status += check_mac(mac, MD5_HASH_SIZE, "9294727a3638bb1c13f48ef8158bfc9d");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, MD5_HASH_SIZE);

	key_size = 4;
	hex_to_block(key, key_size, "4a656665"); // "Jefe"
	hmac_md5(key, key_size, "what do ya want for nothing?", 28, mac, MD5_HASH_SIZE);

	status += check_mac(mac, MD5_HASH_SIZE, "750c783e6ab0b503eaa86e310a5db738");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, MD5_HASH_SIZE);
	memset(data, 0xdd, 50);

	key_size = 16;
	hex_to_block(key, key_size, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	hmac_md5(key, key_size, data, 50, mac, MD5_HASH_SIZE);

	status += check_mac(mac, MD5_HASH_SIZE, "56be34521d144c88dbb8c733f0e8b3f6");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, MD5_HASH_SIZE);
	memset(data, 0xcd, 50);

	key_size = 25;
	hex_to_block(key, key_size, "0102030405060708090a0b0c0d0e0f10111213141516171819");
	hmac_md5(key, key_size, data, 50, mac, MD5_HASH_SIZE);

	status += check_mac(mac, MD5_HASH_SIZE, "697eaf0aca3a3aea3a75164746ffaa79");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, MD5_HASH_SIZE);

	key_size = 16;
	hex_to_block(key, key_size, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
	hmac_md5(key, key_size, "Test With Truncation", 20, mac, 12);

	status += check_mac(mac, 12, "56461ef2342edc00f9bab995");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, MD5_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_md5(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac, MD5_HASH_SIZE);

	status += check_mac(mac, MD5_HASH_SIZE, "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, MD5_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_md5(key, key_size, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73, mac, MD5_HASH_SIZE);

	status += check_mac(mac, MD5_HASH_SIZE, "6f630fad67cda0ee1fb1f562db3aa53e");

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

	status += check_mac(mac, RIPEMD160_HASH_SIZE, "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, RIPEMD160_HASH_SIZE);

	key_size = 4;
	hex_to_block(key, key_size, "4a656665"); // "Jefe"
	hmac_ripemd160(key, key_size, "what do ya want for nothing?", 28, mac, RIPEMD160_HASH_SIZE);

	status += check_mac(mac, RIPEMD160_HASH_SIZE, "dda6c0213a485a9e24f4742064a7f033b43c4069");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, RIPEMD160_HASH_SIZE);
	memset(data, 0xdd, 50);

	key_size = 20;
	hex_to_block(key, key_size, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	hmac_ripemd160(key, key_size, data, 50, mac, RIPEMD160_HASH_SIZE);

	status += check_mac(mac, RIPEMD160_HASH_SIZE, "b0b105360de759960ab4f35298e116e295d8e7c1");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, RIPEMD160_HASH_SIZE);
	memset(data, 0xcd, 50);

	key_size = 25;
	hex_to_block(key, key_size, "0102030405060708090a0b0c0d0e0f10111213141516171819");
	hmac_ripemd160(key, key_size, data, 50, mac, RIPEMD160_HASH_SIZE);

	status += check_mac(mac, RIPEMD160_HASH_SIZE, "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, RIPEMD160_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
	hmac_ripemd160(key, key_size, "Test With Truncation", 20, mac, 12);

	status += check_mac(mac, 12, "7619693978f91d90539ae786");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, RIPEMD160_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_ripemd160(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac, RIPEMD160_HASH_SIZE);

	status += check_mac(mac, RIPEMD160_HASH_SIZE, "6466ca07ac5eac29e1bd523e5ada7605b791fd8b");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, RIPEMD160_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_ripemd160(key, key_size, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73, mac, RIPEMD160_HASH_SIZE);

	status += check_mac(mac, RIPEMD160_HASH_SIZE, "69ea60798d71616cce5fd0871e23754cd75d5a0a");

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

	status += check_mac(mac, SHA1_HASH_SIZE, "b617318655057264e28bc0b6fb378c8ef146be00");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, SHA1_HASH_SIZE);

	key_size = 4;
	hex_to_block(key, key_size, "4a656665"); // "Jefe"
	hmac_sha1(key, key_size, "what do ya want for nothing?", 28, mac, SHA1_HASH_SIZE);

	status += check_mac(mac, SHA1_HASH_SIZE, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, SHA1_HASH_SIZE);
	memset(data, 0xdd, 50);

	key_size = 20;
	hex_to_block(key, key_size, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	hmac_sha1(key, key_size, data, 50, mac, SHA1_HASH_SIZE);

	status += check_mac(mac, SHA1_HASH_SIZE, "125d7342b9ac11cd91a39af48aa17b4f63f175d3");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, SHA1_HASH_SIZE);
	memset(data, 0xcd, 50);

	key_size = 25;
	hex_to_block(key, key_size, "0102030405060708090a0b0c0d0e0f10111213141516171819");
	hmac_sha1(key, key_size, data, 50, mac, SHA1_HASH_SIZE);

	status += check_mac(mac, SHA1_HASH_SIZE, "4c9007f4026250c6bc8414f9bf50c86c2d7235da");

	// ----------------------------------------------------------------------------------------------

	memset(key, 0, 128);
	memset(mac, 0, SHA1_HASH_SIZE);

	key_size = 20;
	hex_to_block(key, key_size, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
	hmac_sha1(key, key_size, "Test With Truncation", 20, mac, 12);

	status += check_mac(mac, 12, "4c1a03424b55e07fe7f27be1");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, SHA1_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_sha1(key, key_size, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac, SHA1_HASH_SIZE);

	status += check_mac(mac, SHA1_HASH_SIZE, "aa4ae5e15272d00e95705637ce8a3b55ed402112");

	// ----------------------------------------------------------------------------------------------

	memset(mac, 0, SHA1_HASH_SIZE);

	key_size = 80;
	memset(key, 0xaa, key_size);
	hmac_sha1(key, key_size, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73, mac, SHA1_HASH_SIZE);

	status += check_mac(mac, SHA1_HASH_SIZE, "e8e99d0f45237d786d6bbaa7965c7808bbff1a91");

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

	status += check_mac(mac_sha224, SHA224_HASH_SIZE, "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
	status += check_mac(mac_sha256, SHA256_HASH_SIZE, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	status += check_mac(mac_sha384, SHA384_HASH_SIZE,
						"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
	status += check_mac(
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

	status += check_mac(mac_sha224, SHA224_HASH_SIZE, "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44");
	status += check_mac(mac_sha256, SHA256_HASH_SIZE, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	status += check_mac(mac_sha384, SHA384_HASH_SIZE,
						"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
	status += check_mac(
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

	status += check_mac(mac_sha224, SHA224_HASH_SIZE, "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea");
	status += check_mac(mac_sha256, SHA256_HASH_SIZE, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
	status += check_mac(mac_sha384, SHA384_HASH_SIZE,
						"88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27");
	status += check_mac(
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

	status += check_mac(mac_sha224, SHA224_HASH_SIZE, "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a");
	status += check_mac(mac_sha256, SHA256_HASH_SIZE, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
	status += check_mac(mac_sha384, SHA384_HASH_SIZE,
						"3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb");
	status += check_mac(
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

	status += check_mac(mac_sha224, 16, "0e2aea68a90c8d37c988bcdb9fca6fa8");
	status += check_mac(mac_sha256, 16, "a3b6167473100ee06e0c796c2955552b");
	status += check_mac(mac_sha384, 16, "3abf34c3503b2a23a46efc619baef897");
	status += check_mac(mac_sha512, 16, "415fad6271580a531d4179bc891d87a6");

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

	status += check_mac(mac_sha224, SHA224_HASH_SIZE, "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e");
	status += check_mac(mac_sha256, SHA256_HASH_SIZE, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
	status += check_mac(mac_sha384, SHA384_HASH_SIZE,
						"4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952");
	status += check_mac(
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

	status += check_mac(mac_sha224, SHA224_HASH_SIZE, "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1");
	status += check_mac(mac_sha256, SHA256_HASH_SIZE, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
	status += check_mac(mac_sha384, SHA384_HASH_SIZE,
						"6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e");
	status += check_mac(
		mac_sha512, SHA512_HASH_SIZE,
		"e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");

	return status;
}

int main()
{
	return hmac_md5_test_suite() + hmac_ripemd160_test_suite() + hmac_sha1_test_suite() + hmac_sha2_test_suite();
}
