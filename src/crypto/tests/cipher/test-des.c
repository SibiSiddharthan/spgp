/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <des.h>

#include "test.h"

// See openssl tests for des

int32_t des_test_suite(void)
{
	int32_t status = 0;
	tdes_key *key = NULL;
	byte_t secret[DES_KEY_SIZE];
	byte_t plaintext[DES_BLOCK_SIZE];
	byte_t ciphertext[DES_BLOCK_SIZE];

	hex_to_block(secret, DES_KEY_SIZE, "0000000000000000");
	hex_to_block(plaintext, DES_BLOCK_SIZE, "0000000000000000");

	key = tdes_key_new(secret, secret, secret, false);

	memset(ciphertext, 0, DES_BLOCK_SIZE);
	tdes_encrypt_block(key, plaintext, ciphertext);
	status += check_block(ciphertext, DES_BLOCK_SIZE, "8ca64de9c1b123a7");

	memset(plaintext, 0, DES_BLOCK_SIZE);
	tdes_decrypt_block(key, ciphertext, plaintext);
	status += check_block(plaintext, DES_BLOCK_SIZE, "0000000000000000");

	tdes_key_delete(key);

	// -------------------------------------------------------------------------

	hex_to_block(secret, DES_KEY_SIZE, "133457799bbcdff1");
	hex_to_block(plaintext, DES_BLOCK_SIZE, "0123456789abcdef");

	key = tdes_key_new(secret, secret, secret, false);

	memset(ciphertext, 0, DES_BLOCK_SIZE);
	tdes_encrypt_block(key, plaintext, ciphertext);
	status += check_block(ciphertext, DES_BLOCK_SIZE, "85e813540f0ab405");

	memset(plaintext, 0, DES_BLOCK_SIZE);
	tdes_decrypt_block(key, ciphertext, plaintext);
	status += check_block(plaintext, DES_BLOCK_SIZE, "0123456789abcdef");

	tdes_key_delete(key);

	// -------------------------------------------------------------------------

	hex_to_block(secret, DES_KEY_SIZE, "0123456789abcdef");
	hex_to_block(plaintext, DES_BLOCK_SIZE, "1111111111111111");

	key = tdes_key_new(secret, secret, secret, false);

	memset(ciphertext, 0, DES_BLOCK_SIZE);
	tdes_encrypt_block(key, plaintext, ciphertext);
	status += check_block(ciphertext, DES_BLOCK_SIZE, "17668dfc7292532d");

	memset(plaintext, 0, DES_BLOCK_SIZE);
	tdes_decrypt_block(key, ciphertext, plaintext);
	status += check_block(plaintext, DES_BLOCK_SIZE, "1111111111111111");

	tdes_key_delete(key);

	return status;
}

int32_t tdes_test_suite(void)
{
	int32_t status = 0;
	tdes_key *key = NULL;
	byte_t secret1[DES_KEY_SIZE], secret2[DES_KEY_SIZE], secret3[DES_KEY_SIZE];
	byte_t plaintext[DES_BLOCK_SIZE];
	byte_t ciphertext[DES_BLOCK_SIZE];

	hex_to_block(secret1, DES_KEY_SIZE, "0123456789abcdef");
	hex_to_block(secret2, DES_KEY_SIZE, "f1e0d3c2b5a49786");
	hex_to_block(secret3, DES_KEY_SIZE, "fedcba9876543210");
	hex_to_block(plaintext, DES_BLOCK_SIZE, "3736353433323120");

	key = tdes_key_new(secret1, secret2, secret3, false);

	memset(ciphertext, 0, DES_BLOCK_SIZE);
	tdes_encrypt_block(key, plaintext, ciphertext);
	status += check_block(ciphertext, DES_BLOCK_SIZE, "62c10cc9efbf15aa");

	memset(plaintext, 0, DES_BLOCK_SIZE);
	tdes_decrypt_block(key, ciphertext, plaintext);
	status += check_block(plaintext, DES_BLOCK_SIZE, "3736353433323120");

	tdes_key_delete(key);

	// -------------------------------------------------------------------------

	hex_to_block(secret1, DES_KEY_SIZE, "0123456789abcdef");
	hex_to_block(secret2, DES_KEY_SIZE, "f1e0d3c2b5a49786");
	hex_to_block(plaintext, DES_BLOCK_SIZE, "3736353433323120");

	hex_to_block(secret1, DES_KEY_SIZE, "0123456789abcdef");
	hex_to_block(secret2, DES_KEY_SIZE, "fedcba9876543210");
	key = tdes_key_new(secret1, secret2, secret1, false);

	memset(ciphertext, 0, DES_BLOCK_SIZE);
	tdes_encrypt_block(key, plaintext, ciphertext);
	status += check_block(ciphertext, DES_BLOCK_SIZE, "4d1332e49f380e23");

	memset(plaintext, 0, DES_BLOCK_SIZE);
	tdes_decrypt_block(key, ciphertext, plaintext);
	status += check_block(plaintext, DES_BLOCK_SIZE, "3736353433323120");

	tdes_key_delete(key);

	return status;
}

int main()
{
	return des_test_suite() + tdes_test_suite();
}
