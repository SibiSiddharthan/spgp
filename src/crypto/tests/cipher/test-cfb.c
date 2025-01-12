/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <cipher.h>

#include <test.h>

// Test vectors taken from NIST

int32_t aes128_cfb1_test_suite(void)
{
	int32_t status = 0;
	byte_t key[16];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(iv, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(plaintext, 2, "6bc1");
	aes128_cfb1_encrypt(key, 16, iv, 16, plaintext, 2, ciphertext, 2);

	status += CHECK_BLOCK(ciphertext, 2, "68b3");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(iv, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(ciphertext, 2, "68b3");
	aes128_cfb1_decrypt(key, 16, iv, 16, ciphertext, 2, plaintext, 2);

	status += CHECK_BLOCK(plaintext, 2, "6bc1");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes128_cfb8_test_suite(void)
{
	int32_t status = 0;
	byte_t key[16];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(iv, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(plaintext, 18, "6bc1bee22e409f96e93d7e117393172aae2d");
	aes128_cfb8_encrypt(key, 16, iv, 16, plaintext, 18, ciphertext, 18);

	status += CHECK_BLOCK(ciphertext, 18, "3b79424c9c0dd436bace9e0ed4586a4f32b9");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(iv, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(ciphertext, 18, "3b79424c9c0dd436bace9e0ed4586a4f32b9");
	aes128_cfb8_decrypt(key, 16, iv, 16, ciphertext, 18, plaintext, 18);

	status += CHECK_BLOCK(plaintext, 18, "6bc1bee22e409f96e93d7e117393172aae2d");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes128_cfb128_test_suite(void)
{
	int32_t status = 0;
	byte_t key[16];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(iv, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(
		plaintext, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
	aes128_cfb128_encrypt(key, 16, iv, 16, plaintext, 64, ciphertext, 64);

	status += CHECK_BLOCK(
		ciphertext, 64,
		"3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(iv, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(
		ciphertext, 64,
		"3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");
	aes128_cfb128_decrypt(key, 16, iv, 16, ciphertext, 64, plaintext, 64);

	status += CHECK_BLOCK(
		plaintext, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_cfb1_test_suite() + aes128_cfb8_test_suite() + aes128_cfb128_test_suite();
}
