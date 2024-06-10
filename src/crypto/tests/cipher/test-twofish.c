/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <twofish.h>

#include <test.h>

// See Twofish: A 128-Bit Block Cipher, Appendix A for test vectors

int32_t twofish128_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[TWOFISH128_KEY_SIZE];
	byte_t plaintext[TWOFISH_BLOCK_SIZE];
	byte_t ciphertext[TWOFISH_BLOCK_SIZE];

	hex_to_block(secret, TWOFISH128_KEY_SIZE, "00000000000000000000000000000000");
	hex_to_block(plaintext, TWOFISH_BLOCK_SIZE, "00000000000000000000000000000000");

	twofish_key *key = twofish_key_new(TWOFISH128, secret, TWOFISH128_KEY_SIZE);

	memset(ciphertext, 0, TWOFISH_BLOCK_SIZE);
	twofish_encrypt_block(key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, TWOFISH_BLOCK_SIZE, "9f589f5cf6122c32b6bfec2f2ae8c35a");

	memset(plaintext, 0, TWOFISH_BLOCK_SIZE);
	twofish_decrypt_block(key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, TWOFISH_BLOCK_SIZE, "00000000000000000000000000000000");

	twofish_key_delete(key);

	return status;
}

int32_t twofish192_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[TWOFISH192_KEY_SIZE];
	byte_t plaintext[TWOFISH_BLOCK_SIZE];
	byte_t ciphertext[TWOFISH_BLOCK_SIZE];

	hex_to_block(secret, TWOFISH192_KEY_SIZE, "0123456789abcdeffedcba98765432100011223344556677");
	hex_to_block(plaintext, TWOFISH_BLOCK_SIZE, "00000000000000000000000000000000");

	twofish_key *key = twofish_key_new(TWOFISH192, secret, TWOFISH192_KEY_SIZE);

	memset(ciphertext, 0, TWOFISH_BLOCK_SIZE);
	twofish_encrypt_block(key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, TWOFISH_BLOCK_SIZE, "cfd1d2e5a9be9cdf501f13b892bd2248");

	memset(plaintext, 0, TWOFISH_BLOCK_SIZE);
	twofish_decrypt_block(key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, TWOFISH_BLOCK_SIZE, "00000000000000000000000000000000");

	twofish_key_delete(key);

	return status;
}

int32_t twofish256_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[TWOFISH256_KEY_SIZE];
	byte_t plaintext[TWOFISH_BLOCK_SIZE];
	byte_t ciphertext[TWOFISH_BLOCK_SIZE];

	hex_to_block(secret, TWOFISH256_KEY_SIZE, "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
	hex_to_block(plaintext, TWOFISH_BLOCK_SIZE, "00000000000000000000000000000000");

	twofish_key *key = twofish_key_new(TWOFISH256, secret, TWOFISH256_KEY_SIZE);

	memset(ciphertext, 0, TWOFISH_BLOCK_SIZE);
	twofish_encrypt_block(key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, TWOFISH_BLOCK_SIZE, "37527be0052334b89f0cfccae87cfa20");

	memset(plaintext, 0, TWOFISH_BLOCK_SIZE);
	twofish_decrypt_block(key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, TWOFISH_BLOCK_SIZE, "00000000000000000000000000000000");

	twofish_key_delete(key);

	return status;
}

int main()
{
	return twofish128_test_suite() + twofish192_test_suite() + twofish256_test_suite();
}
