/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <cipher.h>

#include <test.h>

// Refer RFC 3394: Advanced Encryption Standard (AES) Key Wrap Algorithm
// Refer RFC 5649: Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm

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

int32_t aes192_kew_wrap_pad_test_suite(void)
{
	int32_t status = 0;
	uint32_t result = 0;
	byte_t key[24];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
	hex_to_block(plaintext, 20, "c37b7e6492584340bed12207808941155068f738");

	result = aes192_key_wrap_pad_encrypt(key, 24, plaintext, 20, ciphertext, 64);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(ciphertext, 32, "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");

	memset(plaintext, 0, 64);

	result = aes192_key_wrap_pad_decrypt(key, 24, ciphertext, 32, plaintext, 64);
	status += CHECK_VALUE(result, 20);
	status += CHECK_BLOCK(plaintext, 20, "c37b7e6492584340bed12207808941155068f738");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
	hex_to_block(plaintext, 7, "466f7250617369");

	result = aes192_key_wrap_pad_encrypt(key, 24, plaintext, 7, ciphertext, 64);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "afbeb0f07dfbf5419200f2ccb50bb24f");

	memset(plaintext, 0, 64);

	result = aes192_key_wrap_pad_decrypt(key, 24, ciphertext, 16, plaintext, 64);
	status += CHECK_VALUE(result, 7);
	status += CHECK_BLOCK(plaintext, 7, "466f7250617369");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_kew_wrap_test_suite() + aes192_kew_wrap_test_suite() + aes256_kew_wrap_test_suite() + aes192_kew_wrap_pad_test_suite();
}
