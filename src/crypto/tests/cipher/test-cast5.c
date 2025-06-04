/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <test.h>
#include <cast5.h>


// See RFC 2144: The CAST-128 Encryption Algorithm, Appendix B for test vectors

int32_t cast5_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[CAST5_KEY_SIZE];
	byte_t plaintext[CAST5_BLOCK_SIZE];
	byte_t ciphertext[CAST5_BLOCK_SIZE];

	cast5_key key = {0};

	hex_to_block(secret, CAST5_KEY_SIZE, "0123456712345678234567893456789a");
	hex_to_block(plaintext, CAST5_BLOCK_SIZE, "0123456789abcdef");

	cast5_key_init(&key, secret);

	memset(ciphertext, 0, CAST5_BLOCK_SIZE);
	cast5_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, CAST5_BLOCK_SIZE, "238b4fe5847e44b2");

	memset(plaintext, 0, CAST5_BLOCK_SIZE);
	cast5_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, CAST5_BLOCK_SIZE, "0123456789abcdef");

	return status;
}

int main()
{
	return cast5_test_suite();
}
