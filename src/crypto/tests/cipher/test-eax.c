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

int32_t aes128_eax_suite(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	byte_t key[16];
	byte_t nonce[16];
	byte_t header[64];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "233952dee4d5ed5f9b9c6d6ff80ff478");
	hex_to_block(nonce, 16, "62ec67f9c3a4a407fcb2a8c49031a8b3");
	hex_to_block(header, 8, "6bfb914fd07eae6b");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, NULL, 0, ciphertext, 64);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "e037830e8389f27b025a2d6527e79d01");

	memset(plaintext, 0, 64);
	// result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 16, plaintext, 64);
	// status += CHECK_VALUE(result, 0);

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "91945d3f4dcbee0bf45ef52255f095a4");
	hex_to_block(nonce, 16, "becaf043b0a23d843194ba972c66debd");
	hex_to_block(header, 8, "fa3bfd4806eb53fa");
	hex_to_block(plaintext, 2, "f7fb");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, plaintext, 2, ciphertext, 64);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(ciphertext, 18, "19dd5c4c9331049d0bdab0277408f67967e5");

	memset(plaintext, 0, 64);
	result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 18, plaintext, 64);
	status += CHECK_VALUE(result, 2);
	status += CHECK_BLOCK(plaintext, 2, "f7fb");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01f74ad64077f2e704c0f60ada3dd523");
	hex_to_block(nonce, 16, "70c3db4f0d26368400a10ed05d2bff5e");
	hex_to_block(header, 8, "234a3463c1264ac6");
	hex_to_block(plaintext, 5, "1a47cb4933");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, plaintext, 5, ciphertext, 64);
	status += CHECK_VALUE(result, 21);
	status += CHECK_BLOCK(ciphertext, 21, "d851d5bae03a59f238a23e39199dc9266626c40f80");

	memset(plaintext, 0, 64);
	result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 21, plaintext, 64);
	status += CHECK_VALUE(result, 5);
	status += CHECK_BLOCK(plaintext, 5, "1a47cb4933");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "d07cf6cbb7f313bdde66b727afd3c5e8");
	hex_to_block(nonce, 16, "8408dfff3c1a2b1292dc199e46b7d617");
	hex_to_block(header, 8, "33cce2eabff5a79d");
	hex_to_block(plaintext, 5, "481c9e39b1");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, plaintext, 5, ciphertext, 64);
	status += CHECK_VALUE(result, 21);
	status += CHECK_BLOCK(ciphertext, 21, "632a9d131ad4c168a4225d8e1ff755939974a7bede");

	memset(plaintext, 0, 64);
	result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 21, plaintext, 64);
	status += CHECK_VALUE(result, 5);
	status += CHECK_BLOCK(plaintext, 5, "481c9e39b1");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "35b6d0580005bbc12b0587124557d2c2");
	hex_to_block(nonce, 16, "fdb6b06676eedc5c61d74276e1f8e816");
	hex_to_block(header, 8, "aeb96eaebe2970e9");
	hex_to_block(plaintext, 6, "40d0c07da5e4");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, plaintext, 6, ciphertext, 64);
	status += CHECK_VALUE(result, 22);
	status += CHECK_BLOCK(ciphertext, 22, "071dfe16c675cb0677e536f73afe6a14b74ee49844dd");

	memset(plaintext, 0, 64);
	result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 22, plaintext, 64);
	status += CHECK_VALUE(result, 6);
	status += CHECK_BLOCK(plaintext, 6, "40d0c07da5e4");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "bd8e6e11475e60b268784c38c62feb22");
	hex_to_block(nonce, 16, "6eac5c93072d8e8513f750935e46da1b");
	hex_to_block(header, 8, "d4482d1ca78dce0f");
	hex_to_block(plaintext, 12, "4de3b35c3fc039245bd1fb7d");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, plaintext, 12, ciphertext, 64);
	status += CHECK_VALUE(result, 28);
	status += CHECK_BLOCK(ciphertext, 28, "835bb4f15d743e350e728414abb8644fd6ccb86947c5e10590210a4f");

	memset(plaintext, 0, 64);
	result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 28, plaintext, 64);
	status += CHECK_VALUE(result, 12);
	status += CHECK_BLOCK(plaintext, 12, "4de3b35c3fc039245bd1fb7d");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "7c77d6e813bed5ac98baa417477a2e7d");
	hex_to_block(nonce, 16, "1a8c98dcd73d38393b2bf1569deefc19");
	hex_to_block(header, 8, "65d2017990d62528");
	hex_to_block(plaintext, 17, "8b0a79306c9ce7ed99dae4f87f8dd61636");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, plaintext, 17, ciphertext, 64);
	status += CHECK_VALUE(result, 33);
	status += CHECK_BLOCK(ciphertext, 33, "02083e3979da014812f59f11d52630da30137327d10649b0aa6e1c181db617d7f2");

	memset(plaintext, 0, 64);
	result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 33, plaintext, 64);
	status += CHECK_VALUE(result, 17);
	status += CHECK_BLOCK(plaintext, 17, "8b0a79306c9ce7ed99dae4f87f8dd61636");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "5fff20cafab119ca2fc73549e20f5b0d");
	hex_to_block(nonce, 16, "dde59b97d722156d4d9aff2bc7559826");
	hex_to_block(header, 8, "54b9f04e6a09189a");
	hex_to_block(plaintext, 18, "1bda122bce8a8dbaf1877d962b8592dd2d56");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, plaintext, 18, ciphertext, 64);
	status += CHECK_VALUE(result, 34);
	status += CHECK_BLOCK(ciphertext, 34, "2ec47b2c4954a489afc7ba4897edcdae8cc33b60450599bd02c96382902aef7f832a");

	memset(plaintext, 0, 64);
	result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 34, plaintext, 64);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(plaintext, 18, "1bda122bce8a8dbaf1877d962b8592dd2d56");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "a4a4782bcffd3ec5e7ef6d8c34a56123");
	hex_to_block(nonce, 16, "b781fcf2f75fa5a8de97a9ca48e522ec");
	hex_to_block(header, 8, "899a175897561d7e");
	hex_to_block(plaintext, 18, "6cf36720872b8513f6eab1a8a44438d5ef11");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, plaintext, 18, ciphertext, 64);
	status += CHECK_VALUE(result, 34);
	status += CHECK_BLOCK(ciphertext, 34, "0de18fd0fdd91e7af19f1d8ee8733938b1e8e7f6d2231618102fdb7fe55ff1991700");

	memset(plaintext, 0, 64);
	result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 34, plaintext, 64);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(plaintext, 18, "6cf36720872b8513f6eab1a8a44438d5ef11");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7");
	hex_to_block(nonce, 16, "22e7add93cfc6393c57ec0b3c17d6b44");
	hex_to_block(header, 8, "126735fcc320d25a");
	hex_to_block(plaintext, 21, "8b0a79306c9ce7ed99dae4f87f8dd61636");

	result = aes128_eax_encrypt(key, 16, 16, nonce, 16, header, 8, plaintext, 21, ciphertext, 64);
	status += CHECK_VALUE(result, 37);
	status += CHECK_BLOCK(ciphertext, 37, "cb8920f87a6c75cff39627b56e3ed197c552d295a7cfc46afc253b4652b1af3795b124ab6e");

	memset(plaintext, 0, 64);
	result = aes128_eax_decrypt(key, 16, 16, nonce, 16, header, 8, ciphertext, 37, plaintext, 64);
	status += CHECK_VALUE(result, 21);
	status += CHECK_BLOCK(plaintext, 21, "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_eax_suite();
}