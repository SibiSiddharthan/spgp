/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <cmac.h>
#include <test.h>

// Refer RFC 4493: The AES-CMAC Algorithm, Section 4

int32_t aes128_cmac_test_suite(void)
{
	int32_t status = 0;
	byte_t mac[32] = {0};
	byte_t input[64] = {0};
	byte_t key[32] = {0};

	// ----------------------------------------------------------------------------------------------------------------
	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");

	aes128_cmac(key, 16, NULL, 0, mac, 16);
	status += CHECK_MAC(mac, 16, "bb1d6929e95937287fa37d129b756746");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(input, 16, "6bc1bee22e409f96e93d7e117393172a");

	aes128_cmac(key, 16, input, 16, mac, 16);
	status += CHECK_MAC(mac, 16, "070a16b46b4d4144f79bdd9dd04a287c");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(input, 40, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");

	aes128_cmac(key, 16, input, 40, mac, 16);
	status += CHECK_MAC(mac, 16, "dfa66747de9ae63030ca32611497c827");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2b7e151628aed2a6abf7158809cf4f3c");
	hex_to_block(
		input, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

	aes128_cmac(key, 16, input, 64, mac, 16);
	status += CHECK_MAC(mac, 16, "51f0bebf7e3b9d92fc49741779363cfe");

	// ----------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes192_cmac_test_suite(void)
{
	int32_t status = 0;
	byte_t mac[32] = {0};
	byte_t input[64] = {0};
	byte_t key[32] = {0};

	// ----------------------------------------------------------------------------------------------------------------
	hex_to_block(key, 24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");

	aes192_cmac(key, 24, NULL, 0, mac, 16);
	status += CHECK_MAC(mac, 16, "d17ddf46adaacde531cac483de7a9367");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
	hex_to_block(input, 16, "6bc1bee22e409f96e93d7e117393172a");

	aes192_cmac(key, 24, input, 16, mac, 16);
	status += CHECK_MAC(mac, 16, "9e99a7bf31e710900662f65e617c5184");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
	hex_to_block(input, 20, "6bc1bee22e409f96e93d7e117393172aae2d8a57");

	aes192_cmac(key, 24, input, 20, mac, 16);
	status += CHECK_MAC(mac, 16, "3d75c194ed96070444a9fa7ec740ecf8");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
	hex_to_block(
		input, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

	aes192_cmac(key, 24, input, 64, mac, 16);
	status += CHECK_MAC(mac, 16, "a1d5df0eed790f794d77589659f39a11");

	// ----------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes256_cmac_test_suite(void)
{
	int32_t status = 0;
	byte_t mac[32] = {0};
	byte_t input[64] = {0};
	byte_t key[32] = {0};

	// ----------------------------------------------------------------------------------------------------------------
	hex_to_block(key, 32, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");

	aes256_cmac(key, 32, NULL, 0, mac, 16);
	status += CHECK_MAC(mac, 16, "028962f61b7bf89efc6b551f4667d983");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
	hex_to_block(input, 16, "6bc1bee22e409f96e93d7e117393172a");

	aes256_cmac(key, 32, input, 16, mac, 16);
	status += CHECK_MAC(mac, 16, "28a7023f452e8f82bd4bf28d8c37c35c");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
	hex_to_block(input, 20, "6bc1bee22e409f96e93d7e117393172aae2d8a57");

	aes256_cmac(key, 32, input, 20, mac, 16);
	status += CHECK_MAC(mac, 16, "156727dc0878944a023c1fe03bad6d93");

	// ----------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
	hex_to_block(
		input, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

	aes256_cmac(key, 32, input, 64, mac, 16);
	status += CHECK_MAC(mac, 16, "e1992190549f6ed5696a2c056c315410");

	// ----------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_cmac_test_suite() + aes192_cmac_test_suite() + aes256_cmac_test_suite();
}
