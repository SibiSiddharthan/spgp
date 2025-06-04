/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <test.h>
#include <cipher.h>


// Test vectors taken from NIST

int32_t aes128_ctr_test_suite(void)
{
	int32_t status = 0;
	byte_t key[16];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(iv, 16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	hex_to_block(
		plaintext, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
	aes128_ctr_encrypt(key, 16, iv, 16, plaintext, 64, ciphertext, 64);

	status += CHECK_BLOCK(
		ciphertext, 64,
		"874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(iv, 16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	hex_to_block(
		ciphertext, 64,
		"874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");
	aes128_ctr_decrypt(key, 16, iv, 16, ciphertext, 64, plaintext, 64);

	status += CHECK_BLOCK(
		plaintext, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes192_ctr_test_suite(void)
{
	int32_t status = 0;
	byte_t key[24];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
	hex_to_block(iv, 16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	hex_to_block(
		plaintext, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
	aes192_ctr_encrypt(key, 24, iv, 16, plaintext, 64, ciphertext, 64);

	status += CHECK_BLOCK(
		ciphertext, 64,
		"1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
	hex_to_block(iv, 16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	hex_to_block(
		ciphertext, 64,
		"1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050");
	aes192_ctr_decrypt(key, 24, iv, 16, ciphertext, 64, plaintext, 64);

	status += CHECK_BLOCK(
		plaintext, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes256_ctr_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
	hex_to_block(iv, 16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	hex_to_block(
		plaintext, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
	aes256_ctr_encrypt(key, 32, iv, 16, plaintext, 64, ciphertext, 64);

	status += CHECK_BLOCK(
		ciphertext, 64,
		"601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
	hex_to_block(iv, 16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	hex_to_block(
		ciphertext, 64,
		"601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
	aes256_ctr_decrypt(key, 32, iv, 16, ciphertext, 64, plaintext, 64);

	status += CHECK_BLOCK(
		plaintext, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_ctr_test_suite() + aes192_ctr_test_suite() + aes256_ctr_test_suite();
}
