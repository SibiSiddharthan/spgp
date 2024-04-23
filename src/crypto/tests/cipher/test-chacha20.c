/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <chacha20.h>

#include "test.h"

int32_t chacha20_block_test(void)
{
	int32_t status = 0;
	byte_t secret[CHACHA20_KEY_SIZE];
	byte_t nonce[CHACHA20_NONCE_SIZE];
	byte_t plaintext[CHACHA20_BLOCK_SIZE] = {0};
	byte_t ciphertext[CHACHA20_BLOCK_SIZE] = {0};

	hex_to_block(secret, CHACHA20_KEY_SIZE, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	hex_to_block(nonce, CHACHA20_NONCE_SIZE, "000000090000004a00000000");

	chacha20_key *key = chacha20_new_key(secret, nonce);
	chacha20_encrypt(key, plaintext, ciphertext, CHACHA20_BLOCK_SIZE);
	status += check_block(
		ciphertext, CHACHA20_BLOCK_SIZE,
		"10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");

	chacha20_delete_key(key);

	return status;
}

int32_t chacha20_stream_test(void)
{
	int32_t status = 0;
	byte_t secret[CHACHA20_KEY_SIZE];
	byte_t nonce[CHACHA20_NONCE_SIZE];
	byte_t plaintext[114];
	byte_t ciphertext[114];
	chacha20_key *key = NULL;

	hex_to_block(secret, CHACHA20_KEY_SIZE, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	hex_to_block(nonce, CHACHA20_NONCE_SIZE, "000000000000004a00000000");
	hex_to_block(plaintext, 114,
				 "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796"
				 "f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");

	key = chacha20_new_key(secret, nonce);

	memset(ciphertext, 0, 114);
	chacha20_encrypt(key, plaintext, ciphertext, 114);
	status +=
		check_block(ciphertext, 114,
					"6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c"
					"359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");

	chacha20_delete_key(key);

	key = chacha20_new_key(secret, nonce);

	memset(plaintext, 0, 114);
	chacha20_decrypt(key, ciphertext, plaintext, 114);
	status += check_block(
		plaintext, 114,
		"4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796"
		"f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");

	chacha20_delete_key(key);

	return status;
}

int main()
{
	return chacha20_block_test() + chacha20_stream_test();
}
