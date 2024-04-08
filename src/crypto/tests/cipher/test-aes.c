/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <aes.h>

#include "test.h"

// See NIST FIPS-197 ADVANCED ENCRYPTION STANDARD (AES), Appendix C

int32_t aes128_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[AES128_KEY_SIZE];
	byte_t plaintext[AES_BLOCK_SIZE];
	byte_t ciphertext[AES_BLOCK_SIZE];

	hex_to_block(secret, AES128_KEY_SIZE, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aes_key *key = new_aes_key(AES128, secret);

	memset(ciphertext, 0, AES_BLOCK_SIZE);
	aes_encrypt_block(key, plaintext, ciphertext);
	status += check_block(ciphertext, AES_BLOCK_SIZE, "69c4e0d86a7b0430d8cdb78070b4c55a");

	memset(plaintext, 0, AES_BLOCK_SIZE);
	aes_decrypt_block(key, ciphertext, plaintext);
	status += check_block(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	delete_aes_key(key);

	return status;
}

int32_t aes192_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[AES192_KEY_SIZE];
	byte_t plaintext[AES_BLOCK_SIZE];
	byte_t ciphertext[AES_BLOCK_SIZE];

	hex_to_block(secret, AES192_KEY_SIZE, "000102030405060708090a0b0c0d0e0f1011121314151617");
	hex_to_block(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aes_key *key = new_aes_key(AES192, secret);

	memset(ciphertext, 0, AES_BLOCK_SIZE);
	aes_encrypt_block(key, plaintext, ciphertext);
	status += check_block(ciphertext, AES_BLOCK_SIZE, "dda97ca4864cdfe06eaf70a0ec0d7191");

	memset(plaintext, 0, AES_BLOCK_SIZE);
	aes_decrypt_block(key, ciphertext, plaintext);
	status += check_block(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	delete_aes_key(key);

	return status;
}

int32_t aes256_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[AES256_KEY_SIZE];
	byte_t plaintext[AES_BLOCK_SIZE];
	byte_t ciphertext[AES_BLOCK_SIZE];

	hex_to_block(secret, AES256_KEY_SIZE, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	hex_to_block(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	aes_key *key = new_aes_key(AES256, secret);

	memset(ciphertext, 0, AES_BLOCK_SIZE);
	aes_encrypt_block(key, plaintext, ciphertext);
	status += check_block(ciphertext, AES_BLOCK_SIZE, "8ea2b7ca516745bfeafc49904b496089");

	memset(plaintext, 0, AES_BLOCK_SIZE);
	aes_decrypt_block(key, ciphertext, plaintext);
	status += check_block(plaintext, AES_BLOCK_SIZE, "00112233445566778899aabbccddeeff");

	delete_aes_key(key);

	return status;
}

int main()
{
	return aes128_test_suite() + aes192_test_suite() + aes256_test_suite();
}
