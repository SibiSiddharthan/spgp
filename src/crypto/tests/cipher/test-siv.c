/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cipher.h>

#include <test.h>

// Refer RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption Using AES, Appendix A for test vectors

int32_t aes256_siv_cmac_suite(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	byte_t key[32];
	byte_t ad_1[64];
	byte_t ad_2[64];
	byte_t nonce[64];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	hex_to_block(ad_1, 24, "101112131415161718191a1b1c1d1e1f2021222324252627");
	hex_to_block(plaintext, 14, "112233445566778899aabbccddee");

	void *ads_1[] = {ad_1};
	size_t s_1[] = {24};

	result = aes256_siv_cmac_encrypt(key, 32, ads_1, s_1, 1, NULL, 0, plaintext, 14, ciphertext, 64);
	status += CHECK_VALUE(result, 30);
	status += CHECK_BLOCK(ciphertext, 30, "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");

	memset(plaintext, 0, 64);
	result = aes256_siv_cmac_decrypt(key, 32, ads_1, s_1, 1, NULL, 0, ciphertext, 30, plaintext, 64);
	status += CHECK_VALUE(result, 14);
	status += CHECK_BLOCK(plaintext, 14, "112233445566778899aabbccddee");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
	hex_to_block(ad_1, 40, "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100");
	hex_to_block(ad_2, 10, "102030405060708090a0");
	hex_to_block(nonce, 16, "09f911029d74e35bd84156c5635688c0");
	hex_to_block(plaintext, 47, "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553");

	void *ads_2[] = {ad_1, ad_2};
	size_t s_2[] = {40, 10};

	result = aes256_siv_cmac_encrypt(key, 32, ads_2, s_2, 2, nonce, 16, plaintext, 47, ciphertext, 64);
	status += CHECK_VALUE(result, 63);
	status += CHECK_BLOCK(
		ciphertext, 63,
		"7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d");

	memset(plaintext, 0, 64);
	result = aes256_siv_cmac_decrypt(key, 32, ads_2, s_2, 2, nonce, 16, ciphertext, 63, plaintext, 64);
	status += CHECK_VALUE(result, 47);
	status += CHECK_BLOCK(plaintext, 47, "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes256_siv_cmac_suite();
}
