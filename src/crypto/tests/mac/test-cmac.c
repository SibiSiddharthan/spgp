/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>

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

int main()
{
	return aes128_cmac_test_suite();
}
