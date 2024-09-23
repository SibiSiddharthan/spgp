/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <cipher.h>

#include <test.h>

// Refer RFC 3394: Advanced Encryption Standard (AES) Key Wrap Algorithm

int32_t aes128_kew_wrap_test_suite(void)
{
	int32_t status = 0;
	byte_t key[16];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(plaintext, 16, "00112233445566778899aabbccddeeff");

	aes128_key_wrap_encrypt(key, 16, plaintext, 16, ciphertext, 24);
	status += CHECK_BLOCK(ciphertext, 24, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");

	memset(plaintext, 0, 16);
	aes128_key_wrap_decrypt(key, 16, ciphertext, 24, plaintext, 16);
	status += CHECK_BLOCK(plaintext, 16, "00112233445566778899aabbccddeeff");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes192_kew_wrap_test_suite(void)
{
	int32_t status = 0;
	byte_t key[24];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "000102030405060708090a0b0c0d0e0f1011121314151617");
	hex_to_block(plaintext, 16, "00112233445566778899aabbccddeeff");

	aes192_key_wrap_encrypt(key, 24, plaintext, 16, ciphertext, 24);
	status += CHECK_BLOCK(ciphertext, 24, "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d");

	memset(plaintext, 0, 16);
	aes192_key_wrap_decrypt(key, 24, ciphertext, 24, plaintext, 16);
	status += CHECK_BLOCK(plaintext, 16, "00112233445566778899aabbccddeeff");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "000102030405060708090a0b0c0d0e0f1011121314151617");
	hex_to_block(plaintext, 24, "00112233445566778899aabbccddeeff0001020304050607");

	aes192_key_wrap_encrypt(key, 24, plaintext, 24, ciphertext, 32);
	status += CHECK_BLOCK(ciphertext, 32, "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2");

	memset(plaintext, 0, 24);
	aes192_key_wrap_decrypt(key, 24, ciphertext, 32, plaintext, 24);
	status += CHECK_BLOCK(plaintext, 24, "00112233445566778899aabbccddeeff0001020304050607");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes256_kew_wrap_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	hex_to_block(plaintext, 16, "00112233445566778899aabbccddeeff");

	aes256_key_wrap_encrypt(key, 32, plaintext, 16, ciphertext, 24);
	status += CHECK_BLOCK(ciphertext, 24, "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7");

	memset(plaintext, 0, 24);
	aes256_key_wrap_decrypt(key, 32, ciphertext, 24, plaintext, 16);
	status += CHECK_BLOCK(plaintext, 16, "00112233445566778899aabbccddeeff");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	hex_to_block(plaintext, 24, "00112233445566778899aabbccddeeff0001020304050607");

	aes256_key_wrap_encrypt(key, 32, plaintext, 24, ciphertext, 32);
	status += CHECK_BLOCK(ciphertext, 32, "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1");

	memset(plaintext, 0, 24);
	aes256_key_wrap_decrypt(key, 32, ciphertext, 32, plaintext, 24);
	status += CHECK_BLOCK(plaintext, 24, "00112233445566778899aabbccddeeff0001020304050607");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	hex_to_block(plaintext, 32, "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");

	aes256_key_wrap_encrypt(key, 32, plaintext, 32, ciphertext, 40);
	status += CHECK_BLOCK(ciphertext, 40, "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");

	memset(plaintext, 0, 32);
	aes256_key_wrap_decrypt(key, 32, ciphertext, 40, plaintext, 32);
	status += CHECK_BLOCK(plaintext, 32, "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_kew_wrap_test_suite() + aes192_kew_wrap_test_suite() + aes256_kew_wrap_test_suite();
}
