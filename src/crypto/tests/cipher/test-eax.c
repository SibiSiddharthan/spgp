/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <test.h>
#include <cipher.h>

// Test vectors taken from NIST

int32_t aes128_eax_suite(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[16];
	byte_t nonce[16];
	byte_t tag[16];
	byte_t header[64];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "233952dee4d5ed5f9b9c6d6ff80ff478");
	hex_to_block(nonce, 16, "62ec67f9c3a4a407fcb2a8c49031a8b3");
	hex_to_block(header, 8, "6bfb914fd07eae6b");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, NULL, 0, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "e037830e8389f27b025a2d6527e79d01");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 0, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "e037830e8389f27b025a2d6527e79d01");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "91945d3f4dcbee0bf45ef52255f095a4");
	hex_to_block(nonce, 16, "becaf043b0a23d843194ba972c66debd");
	hex_to_block(header, 8, "fa3bfd4806eb53fa");
	hex_to_block(plaintext, 2, "f7fb");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, plaintext, 2, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 2);
	status += CHECK_BLOCK(ciphertext, 2, "19dd");
	status += CHECK_BLOCK(tag, 16, "5c4c9331049d0bdab0277408f67967e5");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 2, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 2);
	status += CHECK_BLOCK(plaintext, 2, "f7fb");
	status += CHECK_BLOCK(tag, 16, "5c4c9331049d0bdab0277408f67967e5");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01f74ad64077f2e704c0f60ada3dd523");
	hex_to_block(nonce, 16, "70c3db4f0d26368400a10ed05d2bff5e");
	hex_to_block(header, 8, "234a3463c1264ac6");
	hex_to_block(plaintext, 5, "1a47cb4933");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, plaintext, 5, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 5);
	status += CHECK_BLOCK(ciphertext, 5, "d851d5bae0");
	status += CHECK_BLOCK(tag, 16, "3a59f238a23e39199dc9266626c40f80");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 5, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 5);
	status += CHECK_BLOCK(plaintext, 5, "1a47cb4933");
	status += CHECK_BLOCK(tag, 16, "3a59f238a23e39199dc9266626c40f80");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "d07cf6cbb7f313bdde66b727afd3c5e8");
	hex_to_block(nonce, 16, "8408dfff3c1a2b1292dc199e46b7d617");
	hex_to_block(header, 8, "33cce2eabff5a79d");
	hex_to_block(plaintext, 5, "481c9e39b1");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, plaintext, 5, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 5);
	status += CHECK_BLOCK(ciphertext, 5, "632a9d131a");
	status += CHECK_BLOCK(tag, 16, "d4c168a4225d8e1ff755939974a7bede");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 5, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 5);
	status += CHECK_BLOCK(plaintext, 5, "481c9e39b1");
	status += CHECK_BLOCK(tag, 16, "d4c168a4225d8e1ff755939974a7bede");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "35b6d0580005bbc12b0587124557d2c2");
	hex_to_block(nonce, 16, "fdb6b06676eedc5c61d74276e1f8e816");
	hex_to_block(header, 8, "aeb96eaebe2970e9");
	hex_to_block(plaintext, 6, "40d0c07da5e4");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, plaintext, 6, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 6);
	status += CHECK_BLOCK(ciphertext, 6, "071dfe16c675");
	status += CHECK_BLOCK(tag, 16, "cb0677e536f73afe6a14b74ee49844dd");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 6, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 6);
	status += CHECK_BLOCK(plaintext, 6, "40d0c07da5e4");
	status += CHECK_BLOCK(tag, 16, "cb0677e536f73afe6a14b74ee49844dd");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "bd8e6e11475e60b268784c38c62feb22");
	hex_to_block(nonce, 16, "6eac5c93072d8e8513f750935e46da1b");
	hex_to_block(header, 8, "d4482d1ca78dce0f");
	hex_to_block(plaintext, 12, "4de3b35c3fc039245bd1fb7d");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, plaintext, 12, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 12);
	status += CHECK_BLOCK(ciphertext, 12, "835bb4f15d743e350e728414");
	status += CHECK_BLOCK(tag, 16, "abb8644fd6ccb86947c5e10590210a4f");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 12, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 12);
	status += CHECK_BLOCK(plaintext, 12, "4de3b35c3fc039245bd1fb7d");
	status += CHECK_BLOCK(tag, 16, "abb8644fd6ccb86947c5e10590210a4f");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "7c77d6e813bed5ac98baa417477a2e7d");
	hex_to_block(nonce, 16, "1a8c98dcd73d38393b2bf1569deefc19");
	hex_to_block(header, 8, "65d2017990d62528");
	hex_to_block(plaintext, 17, "8b0a79306c9ce7ed99dae4f87f8dd61636");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, plaintext, 17, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 17);
	status += CHECK_BLOCK(ciphertext, 17, "02083e3979da014812f59f11d52630da30");
	status += CHECK_BLOCK(tag, 16, "137327d10649b0aa6e1c181db617d7f2");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 17, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 17);
	status += CHECK_BLOCK(plaintext, 17, "8b0a79306c9ce7ed99dae4f87f8dd61636");
	status += CHECK_BLOCK(tag, 16, "137327d10649b0aa6e1c181db617d7f2");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "5fff20cafab119ca2fc73549e20f5b0d");
	hex_to_block(nonce, 16, "dde59b97d722156d4d9aff2bc7559826");
	hex_to_block(header, 8, "54b9f04e6a09189a");
	hex_to_block(plaintext, 18, "1bda122bce8a8dbaf1877d962b8592dd2d56");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, plaintext, 18, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(ciphertext, 18, "2ec47b2c4954a489afc7ba4897edcdae8cc3");
	status += CHECK_BLOCK(tag, 16, "3b60450599bd02c96382902aef7f832a");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 18, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(plaintext, 18, "1bda122bce8a8dbaf1877d962b8592dd2d56");
	status += CHECK_BLOCK(tag, 16, "3b60450599bd02c96382902aef7f832a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "a4a4782bcffd3ec5e7ef6d8c34a56123");
	hex_to_block(nonce, 16, "b781fcf2f75fa5a8de97a9ca48e522ec");
	hex_to_block(header, 8, "899a175897561d7e");
	hex_to_block(plaintext, 18, "6cf36720872b8513f6eab1a8a44438d5ef11");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, plaintext, 18, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(ciphertext, 18, "0de18fd0fdd91e7af19f1d8ee8733938b1e8");
	status += CHECK_BLOCK(tag, 16, "e7f6d2231618102fdb7fe55ff1991700");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 18, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(plaintext, 18, "6cf36720872b8513f6eab1a8a44438d5ef11");
	status += CHECK_BLOCK(tag, 16, "e7f6d2231618102fdb7fe55ff1991700");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "8395fcf1e95bebd697bd010bc766aac3");
	hex_to_block(nonce, 16, "22e7add93cfc6393c57ec0b3c17d6b44");
	hex_to_block(header, 8, "126735fcc320d25a");
	hex_to_block(plaintext, 21, "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7");
	memset(tag, 0, 16);

	result = aes128_eax_encrypt(key, 16, nonce, 16, header, 8, plaintext, 21, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 21);
	status += CHECK_BLOCK(ciphertext, 21, "cb8920f87a6c75cff39627b56e3ed197c552d295a7");
	status += CHECK_BLOCK(tag, 16, "cfc46afc253b4652b1af3795b124ab6e");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_eax_decrypt(key, 16, nonce, 16, header, 8, ciphertext, 21, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 21);
	status += CHECK_BLOCK(plaintext, 21, "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7");
	status += CHECK_BLOCK(tag, 16, "cfc46afc253b4652b1af3795b124ab6e");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_eax_suite();
}
