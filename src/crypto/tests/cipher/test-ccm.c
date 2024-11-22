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

// Test vectors taken from NIST

int32_t aes128_ccm_suite(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[16];
	byte_t nonce[16];
	byte_t ad[64];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "404142434445464748494a4b4c4d4e4f");
	hex_to_block(nonce, 7, "10111213141516");
	hex_to_block(ad, 8, "0001020304050607");
	hex_to_block(plaintext, 4, "20212223");

	result = aes128_ccm_encrypt(key, 16, 4, nonce, 7, ad, 8, plaintext, 4, ciphertext, 64);
	status += CHECK_VALUE(result, 8);
	status += CHECK_BLOCK(ciphertext, 8, "7162015b4dac255d");

	memset(plaintext, 0, 64);
	result = aes128_ccm_decrypt(key, 16, 4, nonce, 7, ad, 8, ciphertext, 8, plaintext, 64);
	status += CHECK_VALUE(result, 4);
	status += CHECK_BLOCK(plaintext, 4, "20212223");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "404142434445464748494a4b4c4d4e4f");
	hex_to_block(nonce, 8, "1011121314151617");
	hex_to_block(ad, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(plaintext, 16, "202122232425262728292a2b2c2d2e2f");

	result = aes128_ccm_encrypt(key, 16, 6, nonce, 8, ad, 16, plaintext, 16, ciphertext, 64);
	status += CHECK_VALUE(result, 22);
	status += CHECK_BLOCK(ciphertext, 22, "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd");

	memset(plaintext, 0, 64);
	result = aes128_ccm_decrypt(key, 16, 6, nonce, 8, ad, 16, ciphertext, 22, plaintext, 64);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "202122232425262728292a2b2c2d2e2f");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "404142434445464748494a4b4c4d4e4f");
	hex_to_block(nonce, 12, "101112131415161718191a1b");
	hex_to_block(ad, 20, "000102030405060708090a0b0c0d0e0f10111213");
	hex_to_block(plaintext, 24, "202122232425262728292a2b2c2d2e2f3031323334353637");

	result = aes128_ccm_encrypt(key, 16, 8, nonce, 12, ad, 20, plaintext, 24, ciphertext, 64);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(ciphertext, 32, "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951");

	memset(plaintext, 0, 64);
	result = aes128_ccm_decrypt(key, 16, 8, nonce, 12, ad, 20, ciphertext, 32, plaintext, 64);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(plaintext, 24, "202122232425262728292a2b2c2d2e2f3031323334353637");

	// ------------------------------------------------------------------------------------------------------------------------------------

	byte_t *big_ad = malloc(65536);

	hex_to_block(key, 16, "404142434445464748494a4b4c4d4e4f");
	hex_to_block(nonce, 13, "101112131415161718191a1b1c");
	hex_to_block(
		big_ad, 256,
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
		"4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081"
		"82838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2"
		"c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	hex_to_block(plaintext, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

	for (uint32_t i = 256; i < 65536; i += 256)
	{
		memcpy(big_ad + i, big_ad, 256);
	}

	result = aes128_ccm_encrypt(key, 16, 14, nonce, 13, big_ad, 65536, plaintext, 32, ciphertext, 64);
	status += CHECK_VALUE(result, 46);
	status += CHECK_BLOCK(ciphertext, 46, "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b");

	memset(plaintext, 0, 64);
	result = aes128_ccm_decrypt(key, 16, 14, nonce, 13, big_ad, 65536, ciphertext, 46, plaintext, 64);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(plaintext, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

	free(big_ad);

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_ccm_suite();
}
