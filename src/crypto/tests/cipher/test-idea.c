/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <test.h>
#include <idea.h>


// Refer openssl for test vectors

int32_t idea_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[IDEA_KEY_SIZE];
	byte_t plaintext[IDEA_BLOCK_SIZE];
	byte_t ciphertext[IDEA_BLOCK_SIZE];

	idea_key key = {0};

	hex_to_block(secret, IDEA_KEY_SIZE, "00010002000300040005000600070008");
	hex_to_block(plaintext, IDEA_BLOCK_SIZE, "0000000100020003");

	idea_key_init(&key, secret);

	memset(ciphertext, 0, IDEA_BLOCK_SIZE);
	idea_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, IDEA_BLOCK_SIZE, "11fbed2b01986de5");

	memset(plaintext, 0, IDEA_BLOCK_SIZE);
	idea_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, IDEA_BLOCK_SIZE, "0000000100020003");

	return status;
}

int main()
{
	return idea_test_suite();
}
