/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <test.h>
#include <camellia.h>


// See RFC 5794: A Description of the CAMELLIA Encryption Algorithm, Appendix A for test vectors

int32_t camellia128_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[CAMELLIA128_KEY_SIZE];
	byte_t plaintext[CAMELLIA_BLOCK_SIZE];
	byte_t ciphertext[CAMELLIA_BLOCK_SIZE];

	camellia_key key = {0};

	hex_to_block(secret, CAMELLIA128_KEY_SIZE, "0123456789abcdeffedcba9876543210");
	hex_to_block(plaintext, CAMELLIA_BLOCK_SIZE, "0123456789abcdeffedcba9876543210");

	camellia128_key_init(&key, secret);

	memset(ciphertext, 0, CAMELLIA_BLOCK_SIZE);
	camellia128_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, CAMELLIA_BLOCK_SIZE, "67673138549669730857065648eabe43");

	memset(plaintext, 0, CAMELLIA_BLOCK_SIZE);
	camellia128_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, CAMELLIA_BLOCK_SIZE, "0123456789abcdeffedcba9876543210");

	return status;
}

int32_t camellia192_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[CAMELLIA192_KEY_SIZE];
	byte_t plaintext[CAMELLIA_BLOCK_SIZE];
	byte_t ciphertext[CAMELLIA_BLOCK_SIZE];

	camellia_key key = {0};

	hex_to_block(secret, CAMELLIA192_KEY_SIZE, "0123456789abcdeffedcba98765432100011223344556677");
	hex_to_block(plaintext, CAMELLIA_BLOCK_SIZE, "0123456789abcdeffedcba9876543210");

	camellia192_key_init(&key, secret);

	memset(ciphertext, 0, CAMELLIA_BLOCK_SIZE);
	camellia192_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, CAMELLIA_BLOCK_SIZE, "b4993401b3e996f84ee5cee7d79b09b9");

	memset(plaintext, 0, CAMELLIA_BLOCK_SIZE);
	camellia192_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, CAMELLIA_BLOCK_SIZE, "0123456789abcdeffedcba9876543210");

	return status;
}

int32_t camellia256_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[CAMELLIA256_KEY_SIZE];
	byte_t plaintext[CAMELLIA_BLOCK_SIZE];
	byte_t ciphertext[CAMELLIA_BLOCK_SIZE];

	camellia_key key = {0};

	hex_to_block(secret, CAMELLIA256_KEY_SIZE, "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
	hex_to_block(plaintext, CAMELLIA_BLOCK_SIZE, "0123456789abcdeffedcba9876543210");

	camellia256_key_init(&key, secret);

	memset(ciphertext, 0, CAMELLIA_BLOCK_SIZE);
	camellia256_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, CAMELLIA_BLOCK_SIZE, "9acc237dff16d76c20ef7c919e3a7509");

	memset(plaintext, 0, CAMELLIA_BLOCK_SIZE);
	camellia256_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, CAMELLIA_BLOCK_SIZE, "0123456789abcdeffedcba9876543210");

	return status;
}

int main()
{
	return camellia128_test_suite() + camellia192_test_suite() + camellia256_test_suite();
}
