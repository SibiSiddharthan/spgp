/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <aes.h>

#include <test.h>

// See NIST FIPS-197 ADVANCED ENCRYPTION STANDARD (AES), Appendix C

int32_t aes128_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[AES128_KEY_SIZE];
	byte_t plaintext[AES_BLOCK_SIZE];
	byte_t ciphertext[AES_BLOCK_SIZE];

	aes_key key = {0};

	hex_to_block(secret, AES128_KEY_SIZE, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aes128_key_init(&key, secret);

	memset(ciphertext, 0, AES_BLOCK_SIZE);
	aes128_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, AES_BLOCK_SIZE, "69c4e0d86a7b0430d8cdb78070b4c55a");

	memset(plaintext, 0, AES_BLOCK_SIZE);
	aes128_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	return status;
}

int32_t aes192_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[AES192_KEY_SIZE];
	byte_t plaintext[AES_BLOCK_SIZE];
	byte_t ciphertext[AES_BLOCK_SIZE];

	aes_key key = {0};

	hex_to_block(secret, AES192_KEY_SIZE, "000102030405060708090a0b0c0d0e0f1011121314151617");
	hex_to_block(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aes192_key_init(&key, secret);

	memset(ciphertext, 0, AES_BLOCK_SIZE);
	aes192_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, AES_BLOCK_SIZE, "dda97ca4864cdfe06eaf70a0ec0d7191");

	memset(plaintext, 0, AES_BLOCK_SIZE);
	aes192_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	return status;
}

int32_t aes256_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[AES256_KEY_SIZE];
	byte_t plaintext[AES_BLOCK_SIZE];
	byte_t ciphertext[AES_BLOCK_SIZE];

	aes_key key = {0};

	hex_to_block(secret, AES256_KEY_SIZE, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	hex_to_block(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aes256_key_init(&key, secret);

	memset(ciphertext, 0, AES_BLOCK_SIZE);
	aes256_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, AES_BLOCK_SIZE, "8ea2b7ca516745bfeafc49904b496089");

	memset(plaintext, 0, AES_BLOCK_SIZE);
	aes256_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	return status;
}

int main()
{
	return aes128_test_suite() + aes192_test_suite() + aes256_test_suite();
}
