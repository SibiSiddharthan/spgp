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

// Refer RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption Using AES, Appendix A for test vectors

int32_t aes256_siv_cmac_suite(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[32];
	byte_t ad_1[64];
	byte_t ad_2[64];
	byte_t nonce[64];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
	hex_to_block(ad_1, 24, "101112131415161718191a1b1c1d1e1f2021222324252627");
	hex_to_block(plaintext, 14, "112233445566778899aabbccddee");

	void *ads_1[] = {ad_1};
	size_t s_1[] = {24};

	result = aes256_siv_cmac_encrypt(key, 32, ads_1, s_1, 1, NULL, 0, plaintext, 14, ciphertext, 64);
	status += CHECK_VALUE(result, 30);
	status += CHECK_BLOCK(ciphertext, 30, "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");

	memset(plaintext, 0, 64);
	result = aes256_siv_cmac_decrypt(key, 32, ads_1, s_1, 1, NULL, 0, ciphertext, 30, plaintext, 64);
	status += CHECK_VALUE(result, 14);
	status += CHECK_BLOCK(plaintext, 14, "112233445566778899aabbccddee");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
	hex_to_block(ad_1, 40, "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100");
	hex_to_block(ad_2, 10, "102030405060708090a0");
	hex_to_block(nonce, 16, "09f911029d74e35bd84156c5635688c0");
	hex_to_block(plaintext, 47, "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553");

	void *ads_2[] = {ad_1, ad_2};
	size_t s_2[] = {40, 10};

	result = aes256_siv_cmac_encrypt(key, 32, ads_2, s_2, 2, nonce, 16, plaintext, 47, ciphertext, 64);
	status += CHECK_VALUE(result, 63);
	status += CHECK_BLOCK(
		ciphertext, 63,
		"7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d");

	memset(plaintext, 0, 64);
	result = aes256_siv_cmac_decrypt(key, 32, ads_2, s_2, 2, nonce, 16, ciphertext, 63, plaintext, 64);
	status += CHECK_VALUE(result, 47);
	status += CHECK_BLOCK(plaintext, 47, "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

// Refer RFC 8452: AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption, Appendix C for test vectors

int32_t aes128_siv_gcm_suite(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[16];
	byte_t ad[64];
	byte_t nonce[64];
	byte_t plaintext[128];
	byte_t ciphertext[128];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, NULL, 0, NULL, 0, ciphertext, 128);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "dc20e2d83f25705bb49e439eca56de25");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 16, plaintext, 128);
	status += CHECK_VALUE(result, 0);

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 8, "0100000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 8, ciphertext, 128);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(ciphertext, 24, "b5d839330ac7b786578782fff6013b815b287c22493a364c");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 24, plaintext, 128);
	status += CHECK_VALUE(result, 8);
	status += CHECK_BLOCK(plaintext, 8, "0100000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 12, "010000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 12, ciphertext, 128);
	status += CHECK_VALUE(result, 28);
	status += CHECK_BLOCK(ciphertext, 28, "7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 28, plaintext, 128);
	status += CHECK_VALUE(result, 12);
	status += CHECK_BLOCK(plaintext, 12, "010000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 16, "01000000000000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 16, ciphertext, 128);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(ciphertext, 32, "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 32, plaintext, 128);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "01000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 32, "0100000000000000000000000000000002000000000000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 32, ciphertext, 128);
	status += CHECK_VALUE(result, 48);
	status +=
		CHECK_BLOCK(ciphertext, 48, "84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667cd86847bf6155ff");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 48, plaintext, 128);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(plaintext, 32, "0100000000000000000000000000000002000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 48, "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 48, ciphertext, 128);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		ciphertext, 64,
		"3fd24ce1f5a67b75bf2351f181a475c7b800a5b4d3dcf70106b1eea82fa1d64df42bf7226122fa92e17a40eeaac1201b5e6e311dbf395d35b0fe39c2714388f8");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 64, plaintext, 128);
	status += CHECK_VALUE(result, 48);
	status +=
		CHECK_BLOCK(plaintext, 48, "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(
		plaintext, 64,
		"01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 64, ciphertext, 128);
	status += CHECK_VALUE(result, 80);
	status += CHECK_BLOCK(ciphertext, 80,
						  "2433668f1058190f6d43e360f4f35cd8e475127cfca7028ea8ab5c20f7ab2af02516a2bdcbc08d521be37ff28c152bba36697f25b4cd169c"
						  "6590d1dd39566d3f8a263dd317aa88d56bdf3936dba75bb8");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 80, plaintext, 128);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		plaintext, 64,
		"01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 8, "0200000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 1, plaintext, 8, ciphertext, 128);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(ciphertext, 24, "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 1, ciphertext, 24, plaintext, 128);
	status += CHECK_VALUE(result, 8);
	status += CHECK_BLOCK(plaintext, 8, "0200000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 12, "020000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 1, plaintext, 12, ciphertext, 128);
	status += CHECK_VALUE(result, 28);
	status += CHECK_BLOCK(ciphertext, 28, "296c7889fd99f41917f4462008299c5102745aaa3a0c469fad9e075a");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 1, ciphertext, 28, plaintext, 128);
	status += CHECK_VALUE(result, 12);
	status += CHECK_BLOCK(plaintext, 12, "020000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 16, "02000000000000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 1, plaintext, 16, ciphertext, 128);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(ciphertext, 32, "e2b0c5da79a901c1745f700525cb335b8f8936ec039e4e4bb97ebd8c4457441f");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 1, ciphertext, 32, plaintext, 128);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "02000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 32, "0200000000000000000000000000000003000000000000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 1, plaintext, 32, ciphertext, 128);
	status += CHECK_VALUE(result, 48);
	status +=
		CHECK_BLOCK(ciphertext, 48, "620048ef3c1e73e57e02bb8562c416a319e73e4caac8e96a1ecb2933145a1d71e6af6a7f87287da059a71684ed3498e1");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 1, ciphertext, 48, plaintext, 128);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(plaintext, 32, "0200000000000000000000000000000003000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 48, "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 1, plaintext, 48, ciphertext, 128);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		ciphertext, 64,
		"50c8303ea93925d64090d07bd109dfd9515a5a33431019c17d93465999a8b0053201d723120a8562b838cdff25bf9d1e6a8cc3865f76897c2e4b245cf31c51f2");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 1, ciphertext, 64, plaintext, 128);
	status += CHECK_VALUE(result, 48);
	status +=
		CHECK_BLOCK(plaintext, 48, "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(
		plaintext, 64,
		"02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 1, plaintext, 64, ciphertext, 128);
	status += CHECK_VALUE(result, 80);
	status += CHECK_BLOCK(ciphertext, 80,
						  "2f5c64059db55ee0fb847ed513003746aca4e61c711b5de2e7a77ffd02da42feec601910d3467bb8b36ebbaebce5fba30d36c95f48a3e798"
						  "0f0e7ac299332a80cdc46ae475563de037001ef84ae21744");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 1, ciphertext, 80, plaintext, 128);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		plaintext, 64,
		"02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 12, "010000000000000000000000");
	hex_to_block(plaintext, 4, "02000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 12, plaintext, 4, ciphertext, 128);
	status += CHECK_VALUE(result, 20);
	status += CHECK_BLOCK(ciphertext, 20, "a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 12, ciphertext, 20, plaintext, 128);
	status += CHECK_VALUE(result, 4);
	status += CHECK_BLOCK(plaintext, 4, "02000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 18, "010000000000000000000000000000000200");
	hex_to_block(plaintext, 20, "0300000000000000000000000000000004000000");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 18, plaintext, 20, ciphertext, 128);
	status += CHECK_VALUE(result, 36);
	status += CHECK_BLOCK(ciphertext, 36, "6bb0fecf5ded9b77f902c7d5da236a4391dd029724afc9805e976f451e6d87f6fe106514");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 18, ciphertext, 36, plaintext, 128);
	status += CHECK_VALUE(result, 20);
	status += CHECK_BLOCK(plaintext, 20, "0300000000000000000000000000000004000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "01000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 20, "0100000000000000000000000000000002000000");
	hex_to_block(plaintext, 18, "030000000000000000000000000000000400");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 20, plaintext, 18, ciphertext, 128);
	status += CHECK_VALUE(result, 34);
	status += CHECK_BLOCK(ciphertext, 34, "44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13b9fd");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 20, ciphertext, 34, plaintext, 128);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(plaintext, 18, "030000000000000000000000000000000400");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "e66021d5eb8e4f4066d4adb9c33560e4");
	hex_to_block(nonce, 12, "f46e44bb3da0015c94f70887");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, NULL, 0, NULL, 0, ciphertext, 128);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "a4194b79071b01a87d65f706e3949578");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 16, plaintext, 128);
	status += CHECK_VALUE(result, 0);

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "36864200e0eaf5284d884a0e77d31646");
	hex_to_block(nonce, 12, "bae8e37fc83441b16034566b");
	hex_to_block(ad, 5, "46bb91c3c5");
	hex_to_block(plaintext, 3, "7a806c");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 5, plaintext, 3, ciphertext, 128);
	status += CHECK_VALUE(result, 19);
	status += CHECK_BLOCK(ciphertext, 19, "af60eb711bd85bc1e4d3e0a462e074eea428a8");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 5, ciphertext, 19, plaintext, 128);
	status += CHECK_VALUE(result, 3);
	status += CHECK_BLOCK(plaintext, 3, "7a806c");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "aedb64a6c590bc84d1a5e269e4b47801");
	hex_to_block(nonce, 12, "afc0577e34699b9e671fdd4f");
	hex_to_block(ad, 10, "fc880c94a95198874296");
	hex_to_block(plaintext, 6, "bdc66f146545");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 10, plaintext, 6, ciphertext, 128);
	status += CHECK_VALUE(result, 22);
	status += CHECK_BLOCK(ciphertext, 22, "bb93a3e34d3cd6a9c45545cfc11f03ad743dba20f966");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 10, ciphertext, 22, plaintext, 128);
	status += CHECK_VALUE(result, 6);
	status += CHECK_BLOCK(plaintext, 6, "bdc66f146545");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "d5cc1fd161320b6920ce07787f86743b");
	hex_to_block(nonce, 12, "275d1ab32f6d1f0434d8848c");
	hex_to_block(ad, 15, "046787f3ea22c127aaf195d1894728");
	hex_to_block(plaintext, 9, "1177441f195495860f");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 15, plaintext, 9, ciphertext, 128);
	status += CHECK_VALUE(result, 25);
	status += CHECK_BLOCK(ciphertext, 25, "4f37281f7ad12949d01d02fd0cd174c84fc5dae2f60f52fd2b");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 15, ciphertext, 25, plaintext, 128);
	status += CHECK_VALUE(result, 9);
	status += CHECK_BLOCK(plaintext, 9, "1177441f195495860f");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "b3fed1473c528b8426a582995929a149");
	hex_to_block(nonce, 12, "9e9ad8780c8d63d0ab4149c0");
	hex_to_block(ad, 20, "c9882e5386fd9f92ec489c8fde2be2cf97e74e93");
	hex_to_block(plaintext, 12, "9f572c614b4745914474e7c7");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 20, plaintext, 12, ciphertext, 128);
	status += CHECK_VALUE(result, 28);
	status += CHECK_BLOCK(ciphertext, 28, "f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 20, ciphertext, 28, plaintext, 128);
	status += CHECK_VALUE(result, 12);
	status += CHECK_BLOCK(plaintext, 12, "9f572c614b4745914474e7c7");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2d4ed87da44102952ef94b02b805249b");
	hex_to_block(nonce, 12, "ac80e6f61455bfac8308a2d4");
	hex_to_block(ad, 25, "2950a70d5a1db2316fd568378da107b52b0da55210cc1c1b0a");
	hex_to_block(plaintext, 15, "0d8c8451178082355c9e940fea2f58");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 25, plaintext, 15, ciphertext, 128);
	status += CHECK_VALUE(result, 31);
	status += CHECK_BLOCK(ciphertext, 31, "c9ff545e07b88a015f05b274540aa183b3449b9f39552de99dc214a1190b0b");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 25, ciphertext, 31, plaintext, 128);
	status += CHECK_VALUE(result, 15);
	status += CHECK_BLOCK(plaintext, 15, "0d8c8451178082355c9e940fea2f58");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "bde3b2f204d1e9f8b06bc47f9745b3d1");
	hex_to_block(nonce, 12, "ae06556fb6aa7890bebc18fe");
	hex_to_block(ad, 30, "1860f762ebfbd08284e421702de0de18baa9c9596291b08466f37de21c7f");
	hex_to_block(plaintext, 18, "6b3db4da3d57aa94842b9803a96e07fb6de7");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 30, plaintext, 18, ciphertext, 128);
	status += CHECK_VALUE(result, 34);
	status += CHECK_BLOCK(ciphertext, 34, "6298b296e24e8cc35dce0bed484b7f30d5803e377094f04709f64d7b985310a4db84");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 30, ciphertext, 34, plaintext, 128);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(plaintext, 18, "6b3db4da3d57aa94842b9803a96e07fb6de7");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "f901cfe8a69615a93fdf7a98cad48179");
	hex_to_block(nonce, 12, "6245709fb18853f68d833640");
	hex_to_block(ad, 35, "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21");
	hex_to_block(plaintext, 21, "e42a3c02c25b64869e146d7b233987bddfc240871d");

	result = aes128_siv_gcm_encrypt(key, 16, nonce, 12, ad, 35, plaintext, 21, ciphertext, 128);
	status += CHECK_VALUE(result, 37);
	status += CHECK_BLOCK(ciphertext, 37, "391cc328d484a4f46406181bcd62efd9b3ee197d052d15506c84a9edd65e13e9d24a2a6e70");

	memset(plaintext, 0, 128);
	result = aes128_siv_gcm_decrypt(key, 16, nonce, 12, ad, 35, ciphertext, 37, plaintext, 128);
	status += CHECK_VALUE(result, 21);
	status += CHECK_BLOCK(plaintext, 21, "e42a3c02c25b64869e146d7b233987bddfc240871d");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes256_siv_gcm_suite(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[32];
	byte_t ad[64];
	byte_t nonce[64];
	byte_t plaintext[128];
	byte_t ciphertext[128];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, NULL, 0, ciphertext, 128);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "07f5f4169bbf55a8400cd47ea6fd400f");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 16, plaintext, 128);
	status += CHECK_VALUE(result, 0);

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 8, "0100000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, plaintext, 8, ciphertext, 128);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(ciphertext, 24, "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 24, plaintext, 128);
	status += CHECK_VALUE(result, 8);
	status += CHECK_BLOCK(plaintext, 8, "0100000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 12, "010000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, plaintext, 12, ciphertext, 128);
	status += CHECK_VALUE(result, 28);
	status += CHECK_BLOCK(ciphertext, 28, "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 28, plaintext, 128);
	status += CHECK_VALUE(result, 12);
	status += CHECK_BLOCK(plaintext, 12, "010000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 16, "01000000000000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, plaintext, 16, ciphertext, 128);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(ciphertext, 32, "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 32, plaintext, 128);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "01000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 32, "0100000000000000000000000000000002000000000000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, plaintext, 32, ciphertext, 128);
	status += CHECK_VALUE(result, 48);
	status +=
		CHECK_BLOCK(ciphertext, 48, "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 48, plaintext, 128);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(plaintext, 32, "0100000000000000000000000000000002000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(plaintext, 48, "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, plaintext, 48, ciphertext, 128);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		ciphertext, 64,
		"c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e39cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 64, plaintext, 128);
	status += CHECK_VALUE(result, 48);
	status +=
		CHECK_BLOCK(plaintext, 48, "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(
		plaintext, 64,
		"01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, plaintext, 64, ciphertext, 128);
	status += CHECK_VALUE(result, 80);
	status += CHECK_BLOCK(ciphertext, 80,
						  "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891a4db8caaa1f99dd004d8048754073523"
						  "4e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 80, plaintext, 128);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		plaintext, 64,
		"01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 8, "0200000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 1, plaintext, 8, ciphertext, 128);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(ciphertext, 24, "1de22967237a813291213f267e3b452f02d01ae33e4ec854");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 1, ciphertext, 24, plaintext, 128);
	status += CHECK_VALUE(result, 8);
	status += CHECK_BLOCK(plaintext, 8, "0200000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 12, "020000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 1, plaintext, 12, ciphertext, 128);
	status += CHECK_VALUE(result, 28);
	status += CHECK_BLOCK(ciphertext, 28, "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 1, ciphertext, 28, plaintext, 128);
	status += CHECK_VALUE(result, 12);
	status += CHECK_BLOCK(plaintext, 12, "020000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 16, "02000000000000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 1, plaintext, 16, ciphertext, 128);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(ciphertext, 32, "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 1, ciphertext, 32, plaintext, 128);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "02000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 32, "0200000000000000000000000000000003000000000000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 1, plaintext, 32, ciphertext, 128);
	status += CHECK_VALUE(result, 48);
	status +=
		CHECK_BLOCK(ciphertext, 48, "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365aea1bad12702e1965604374aab96dbbc");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 1, ciphertext, 48, plaintext, 128);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(plaintext, 32, "0200000000000000000000000000000003000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(plaintext, 48, "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 1, plaintext, 48, ciphertext, 128);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		ciphertext, 64,
		"c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 1, ciphertext, 64, plaintext, 128);
	status += CHECK_VALUE(result, 48);
	status +=
		CHECK_BLOCK(plaintext, 48, "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 1, "01");
	hex_to_block(
		plaintext, 64,
		"02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 1, plaintext, 64, ciphertext, 128);
	status += CHECK_VALUE(result, 80);
	status += CHECK_BLOCK(ciphertext, 80,
						  "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc98cb933a8fce9de887b1e40799988db1fc3f91880ed405b2d"
						  "d298318858467c895bde0285037c5de81e5b570a049b62a0");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 1, ciphertext, 80, plaintext, 128);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		plaintext, 64,
		"02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 12, "010000000000000000000000");
	hex_to_block(plaintext, 4, "02000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 12, plaintext, 4, ciphertext, 128);
	status += CHECK_VALUE(result, 20);
	status += CHECK_BLOCK(ciphertext, 20, "22b3f4cd1835e517741dfddccfa07fa4661b74cf");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 12, ciphertext, 20, plaintext, 128);
	status += CHECK_VALUE(result, 4);
	status += CHECK_BLOCK(plaintext, 4, "02000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 18, "010000000000000000000000000000000200");
	hex_to_block(plaintext, 20, "0300000000000000000000000000000004000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 18, plaintext, 20, ciphertext, 128);
	status += CHECK_VALUE(result, 36);
	status += CHECK_BLOCK(ciphertext, 36, "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59cabfe307");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 18, ciphertext, 36, plaintext, 128);
	status += CHECK_VALUE(result, 20);
	status += CHECK_BLOCK(plaintext, 20, "0300000000000000000000000000000004000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0100000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "030000000000000000000000");
	hex_to_block(ad, 20, "0100000000000000000000000000000002000000");
	hex_to_block(plaintext, 18, "030000000000000000000000000000000400");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 20, plaintext, 18, ciphertext, 128);
	status += CHECK_VALUE(result, 34);
	status += CHECK_BLOCK(ciphertext, 34, "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 20, ciphertext, 34, plaintext, 128);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(plaintext, 18, "030000000000000000000000000000000400");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200");
	hex_to_block(nonce, 12, "e0eaf5284d884a0e77d31646");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, NULL, 0, ciphertext, 128);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "169fbb2fbf389a995f6390af22228a62");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 16, plaintext, 128);
	status += CHECK_VALUE(result, 0);

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269");
	hex_to_block(nonce, 12, "e4b47801afc0577e34699b9e");
	hex_to_block(ad, 5, "4fbdc66f14");
	hex_to_block(plaintext, 3, "671fdd");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 5, plaintext, 3, ciphertext, 128);
	status += CHECK_VALUE(result, 19);
	status += CHECK_BLOCK(ciphertext, 19, "0eaccb93da9bb81333aee0c785b240d319719d");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 5, ciphertext, 19, plaintext, 128);
	status += CHECK_VALUE(result, 3);
	status += CHECK_BLOCK(plaintext, 3, "671fdd");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3");
	hex_to_block(nonce, 12, "2f6d1f0434d8848c1177441f");
	hex_to_block(ad, 10, "6787f3ea22c127aaf195");
	hex_to_block(plaintext, 6, "195495860f04");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 10, plaintext, 6, ciphertext, 128);
	status += CHECK_VALUE(result, 22);
	status += CHECK_BLOCK(ciphertext, 22, "a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 10, ciphertext, 22, plaintext, 128);
	status += CHECK_VALUE(result, 6);
	status += CHECK_BLOCK(plaintext, 6, "195495860f04");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0");
	hex_to_block(nonce, 12, "9f572c614b4745914474e7c7");
	hex_to_block(ad, 15, "489c8fde2be2cf97e74e932d4ed87d");
	hex_to_block(plaintext, 9, "c9882e5386fd9f92ec");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 15, plaintext, 9, ciphertext, 128);
	status += CHECK_VALUE(result, 25);
	status += CHECK_BLOCK(ciphertext, 25, "0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 15, ciphertext, 25, plaintext, 128);
	status += CHECK_VALUE(result, 9);
	status += CHECK_BLOCK(plaintext, 9, "c9882e5386fd9f92ec");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235");
	hex_to_block(nonce, 12, "5c9e940fea2f582950a70d5a");
	hex_to_block(ad, 20, "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f");
	hex_to_block(plaintext, 12, "1db2316fd568378da107b52b");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 20, plaintext, 12, ciphertext, 128);
	status += CHECK_VALUE(result, 28);
	status += CHECK_BLOCK(ciphertext, 28, "8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 20, ciphertext, 28, plaintext, 128);
	status += CHECK_VALUE(result, 12);
	status += CHECK_BLOCK(plaintext, 12, "1db2316fd568378da107b52b");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb");
	hex_to_block(nonce, 12, "6de71860f762ebfbd08284e4");
	hex_to_block(ad, 25, "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f");
	hex_to_block(plaintext, 15, "21702de0de18baa9c9596291b08466");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 25, plaintext, 15, ciphertext, 128);
	status += CHECK_VALUE(result, 31);
	status += CHECK_BLOCK(ciphertext, 31, "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 25, ciphertext, 31, plaintext, 128);
	status += CHECK_VALUE(result, 15);
	status += CHECK_BLOCK(plaintext, 15, "21702de0de18baa9c9596291b08466");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7");
	hex_to_block(nonce, 12, "028ec6eb5ea7e298342a94d4");
	hex_to_block(ad, 30, "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7");
	hex_to_block(plaintext, 18, "b202b370ef9768ec6561c4fe6b7e7296fa85");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 30, plaintext, 18, ciphertext, 128);
	status += CHECK_VALUE(result, 34);
	status += CHECK_BLOCK(ciphertext, 34, "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d0a49");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 30, ciphertext, 34, plaintext, 128);
	status += CHECK_VALUE(result, 18);
	status += CHECK_BLOCK(plaintext, 18, "b202b370ef9768ec6561c4fe6b7e7296fa85");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23");
	hex_to_block(nonce, 12, "688089e55540db1872504e1c");
	hex_to_block(ad, 35, "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541");
	hex_to_block(plaintext, 21, "ced532ce4159b035277d4dfbb7db62968b13cd4eec");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, ad, 35, plaintext, 21, ciphertext, 128);
	status += CHECK_VALUE(result, 37);
	status += CHECK_BLOCK(ciphertext, 37, "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a286594");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, ad, 35, ciphertext, 37, plaintext, 128);
	status += CHECK_VALUE(result, 21);
	status += CHECK_BLOCK(plaintext, 21, "ced532ce4159b035277d4dfbb7db62968b13cd4eec");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes256_siv_gcm_wrap_tests(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[32];
	byte_t nonce[64];
	byte_t plaintext[128];
	byte_t ciphertext[128];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0000000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "000000000000000000000000");
	hex_to_block(plaintext, 32, "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, plaintext, 32, ciphertext, 128);
	status += CHECK_VALUE(result, 48);
	status +=
		CHECK_BLOCK(ciphertext, 48, "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3eaffffffff000000000000000000000000");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 48, plaintext, 128);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(plaintext, 32, "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0000000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(nonce, 12, "000000000000000000000000");
	hex_to_block(plaintext, 24, "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000");

	result = aes256_siv_gcm_encrypt(key, 32, nonce, 12, NULL, 0, plaintext, 24, ciphertext, 128);
	status += CHECK_VALUE(result, 40);
	status += CHECK_BLOCK(ciphertext, 40, "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff000000000000000000000000");

	memset(plaintext, 0, 128);
	result = aes256_siv_gcm_decrypt(key, 32, nonce, 12, NULL, 0, ciphertext, 40, plaintext, 128);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(plaintext, 24, "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes256_siv_cmac_suite() + aes128_siv_gcm_suite() + aes256_siv_gcm_suite() + aes256_siv_gcm_wrap_tests();
}
