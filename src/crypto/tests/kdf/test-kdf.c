/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>

#include <hmac.h>
#include <kdf.h>
#include <test.h>

// Test vectors taken from NIST

int32_t kdf_counter_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];
	byte_t input[64];
	byte_t output[32];

	hex_to_block(key, 32, "dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0");
	hex_to_block(
		input, 60,
		"01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac");
	kdf(KDF_MODE_COUNTER, KDF_PRF_HMAC, HMAC_SHA256, key, 32, input, 60, NULL, 0, NULL, 0, NULL, 0, output, 16);
	status += CHECK_BLOCK(output, 16, "10621342bfb0fd40046c0e29f2cfdbf0");

	hex_to_block(key, 32, "e204d6d466aad507ffaf6d6dab0a5b26152c9e21e764370464e360c8fbc765c6");
	hex_to_block(
		input, 60,
		"7b03b98d9f94b899e591f3ef264b71b193fba7043c7e953cde23bc5384bc1a6293580115fae3495fd845dadbd02bd6455cf48d0f62b33e62364a3a80");
	kdf(KDF_MODE_COUNTER, KDF_PRF_HMAC, HMAC_SHA256, key, 32, input, 60, NULL, 0, NULL, 0, NULL, 0, output, 32);
	status += CHECK_BLOCK(output, 32, "770dfab6a6a4a4bee0257ff335213f78d8287b4fd537d5c1fffa956910e7c779");

	hex_to_block(key, 32, "1d9209183e557d3aac7e2ab53d26ec659df2a745fe56a53818ef5853a42ce194");
	hex_to_block(
		input, 60,
		"c01a431a32833930a22abee5c6ea34db459316def3b241529ece7e39e2069a1e6b942946132eebc9679801d2cefef4bbb6a1b84ef853325b7bc498fd");
	kdf(KDF_MODE_COUNTER, KDF_PRF_HMAC, HMAC_SHA256, key, 32, input, 60, NULL, 0, NULL, 0, NULL, 0, output, 40);
	status += CHECK_BLOCK(output, 40, "dabcffa16a7589deee6c768aaf01e0813de909005526da54700083ef068f854d49941279689a1726");

	return status;
}

int main()
{
	return kdf_counter_test_suite();
}
