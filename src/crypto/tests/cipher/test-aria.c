/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <aria.h>

#include <test.h>

// See RFC 5794: A Description of the ARIA Encryption Algorithm, Appendix A for test vectors

int32_t aria128_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[ARIA128_KEY_SIZE];
	byte_t plaintext[ARIA_BLOCK_SIZE];
	byte_t ciphertext[ARIA_BLOCK_SIZE];

	hex_to_block(secret, ARIA128_KEY_SIZE, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(plaintext, ARIA_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aria_key *key = aria_key_new(ARIA128, secret,ARIA128_KEY_SIZE);

	memset(ciphertext, 0, ARIA_BLOCK_SIZE);
	aria_encrypt_block(key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, ARIA_BLOCK_SIZE, "d718fbd6ab644c739da95f3be6451778");

	memset(plaintext, 0, ARIA_BLOCK_SIZE);
	aria_decrypt_block(key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, ARIA_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aria_key_delete(key);

	return status;
}

int32_t aria192_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[ARIA192_KEY_SIZE];
	byte_t plaintext[ARIA_BLOCK_SIZE];
	byte_t ciphertext[ARIA_BLOCK_SIZE];

	hex_to_block(secret, ARIA192_KEY_SIZE, "000102030405060708090a0b0c0d0e0f1011121314151617");
	hex_to_block(plaintext, ARIA_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aria_key *key = aria_key_new(ARIA192, secret, ARIA192_KEY_SIZE);

	memset(ciphertext, 0, ARIA_BLOCK_SIZE);
	aria_encrypt_block(key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, ARIA_BLOCK_SIZE, "26449c1805dbe7aa25a468ce263a9e79");

	memset(plaintext, 0, ARIA_BLOCK_SIZE);
	aria_decrypt_block(key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, ARIA_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aria_key_delete(key);

	return status;
}

int32_t aria256_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[ARIA256_KEY_SIZE];
	byte_t plaintext[ARIA_BLOCK_SIZE];
	byte_t ciphertext[ARIA_BLOCK_SIZE];

	hex_to_block(secret, ARIA256_KEY_SIZE, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	hex_to_block(plaintext, ARIA_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aria_key *key = aria_key_new(ARIA256, secret, ARIA256_KEY_SIZE);

	memset(ciphertext, 0, ARIA_BLOCK_SIZE);
	aria_encrypt_block(key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, ARIA_BLOCK_SIZE, "f92bd7c79fb72e2f2b8f80c1972d24fc");

	memset(plaintext, 0, ARIA_BLOCK_SIZE);
	aria_decrypt_block(key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, ARIA_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aria_key_delete(key);

	return status;
}

int main()
{
	return aria128_test_suite() + aria192_test_suite() + aria256_test_suite();
}
