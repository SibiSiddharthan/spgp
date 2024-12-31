/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

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
	byte_t output[64];

	hex_to_block(key, 32, "dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0");
	hex_to_block(
		input, 60,
		"01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac");
	kdf(KDF_MODE_COUNTER, KDF_PRF_HMAC, HASH_SHA256, key, 32, input, 60, NULL, 0, NULL, 0, NULL, 0, output, 16);
	status += CHECK_BLOCK(output, 16, "10621342bfb0fd40046c0e29f2cfdbf0");

	hex_to_block(key, 32, "e204d6d466aad507ffaf6d6dab0a5b26152c9e21e764370464e360c8fbc765c6");
	hex_to_block(
		input, 60,
		"7b03b98d9f94b899e591f3ef264b71b193fba7043c7e953cde23bc5384bc1a6293580115fae3495fd845dadbd02bd6455cf48d0f62b33e62364a3a80");
	kdf(KDF_MODE_COUNTER, KDF_PRF_HMAC, HASH_SHA256, key, 32, input, 60, NULL, 0, NULL, 0, NULL, 0, output, 32);
	status += CHECK_BLOCK(output, 32, "770dfab6a6a4a4bee0257ff335213f78d8287b4fd537d5c1fffa956910e7c779");

	hex_to_block(key, 32, "1d9209183e557d3aac7e2ab53d26ec659df2a745fe56a53818ef5853a42ce194");
	hex_to_block(
		input, 60,
		"c01a431a32833930a22abee5c6ea34db459316def3b241529ece7e39e2069a1e6b942946132eebc9679801d2cefef4bbb6a1b84ef853325b7bc498fd");
	kdf(KDF_MODE_COUNTER, KDF_PRF_HMAC, HASH_SHA256, key, 32, input, 60, NULL, 0, NULL, 0, NULL, 0, output, 40);
	status += CHECK_BLOCK(output, 40, "dabcffa16a7589deee6c768aaf01e0813de909005526da54700083ef068f854d49941279689a1726");

	return status;
}

int32_t kdf_feedback_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];
	byte_t iv[32];
	byte_t input[64];
	byte_t output[256];

	hex_to_block(key, 32, "93f698e842eed75394d629d957e2e89c6e741f810b623c8b901e38376d068e7b");
	hex_to_block(iv, 32, "9f575d9059d3e0c0803f08112f8a806de3c3471912cdf42b095388b14b33508e");
	hex_to_block(input, 51, "53b89c18690e2057a1d167822e636de50be0018532c431f7f5e37f77139220d5e042599ebe266af5767ee18cd2c5c19a1f0f80");
	kdf(KDF_MODE_FEEDBACK, KDF_PRF_HMAC, HASH_SHA256, key, 32, input, 51, NULL, 0, NULL, 0, iv, 32, output, 64);
	status += CHECK_BLOCK(
		output, 64,
		"bd1476f43a4e315747cf5918e0ea5bc0d98769457477c3ab18b742def0e079a933b756365afb5541f253fee43c6fd788a44041038509e9eeb68f7d65ffbb5f95");

	hex_to_block(key, 32, "a5eb2ebcb9cc7aa0ee9f38cdcc18956a041714369acbcb722d995010f2b8463d");
	hex_to_block(iv, 32, "11be2ef7753959c3c070d49afce9c4d09ad8311a14e03bcf9edc2c11fe6950b4");
	hex_to_block(input, 51, "8f71ffd48fe4680cb13582f5c977c99fd6c4aa8012378857989b52fbee90d358df1e58802db0a31f562d064a9c42cb44136ee9");
	kdf(KDF_MODE_FEEDBACK, KDF_PRF_HMAC, HASH_SHA256, key, 32, input, 51, NULL, 0, NULL, 0, iv, 32, output, 256);
	status += CHECK_BLOCK(
		output, 256,
		"0aa2002a47da3d5f840bbb4fdc7fec52583a3d9734d8f69f76983803f10ec2872ad88baec5234e30f84022dcec260072a65047ad6ea7bb0646c71012b8684c0d7a"
		"0bd018ed4e23a289640a0d9c7c1885d310d933fd3fab5a20b1667da6e403a23909fac35bc1e80b7b82de2ed8b105a1a34a9754a954f95353d7c2f00a6beefed72a"
		"b38a7b638304c1b712027cd16d3dc9735db2fcb2f05712b490080c0feb94827bda60f0f47eb449eafb85380187e6df31c2f0660027f086ea5b5965e4d705ae7db9"
		"959a8e87acdcde604039a0fbfa72274b8339cdb3d53f432229125d20f3800db4351b4754742b2d6426a8e24076f349c589409feb45ff65738fd3d77168");

	hex_to_block(key, 32, "833ab78dc0a2700c2ed8775c1565583895ab58760206675f25829f883dedaf6b");
	hex_to_block(iv, 32, "14aef75054bf33d2e7417535fd8d9f8a872a8121d91eb5bf15f2799d2b5c7701");
	hex_to_block(input, 51, "645fe69ba5377ec8d54cb2a774bf45bd008f7ac491e818f1835dc7b03b2df5a1812cc76d24185e5a962be381dd2ed3f48cf30d");
	kdf(KDF_MODE_FEEDBACK, KDF_PRF_HMAC, HASH_SHA256, key, 32, input, 51, NULL, 0, NULL, 0, iv, 32, output, 70);
	status += CHECK_BLOCK(output, 70,
						  "f0025aa175fc9b880abf4f4ee741c6d11d88286f43d2fa8ea4e96b55b075227c1c84a5797da8431fd8811274c7071627c3fae554bd0d4cce"
						  "9074e98f5ecfa51ba67704efcc24");

	return status;
}

int32_t kdf_double_pipeline_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];
	byte_t input[64];
	byte_t output[256];

	hex_to_block(key, 32, "02d36fa021c20ddbdee469f0579468bae5cb13b548b6c61cdf9d3ec419111de2");
	hex_to_block(input, 51, "85abe38bf265fbdc6445ae5c71159f1548c73b7d526a623104904a0f8792070b3df9902b9669490425a385eadb0f9c76e46f0f");
	kdf(KDF_MODE_DOUBLE_PIPLELINE, KDF_PRF_HMAC, HASH_SHA256, key, 32, input, 51, NULL, 0, NULL, 0, NULL, 0, output, 64);
	status += CHECK_BLOCK(
		output, 64,
		"d69f74f518c9f64f90a0beebab69f689b73b5c13eb0f860a95cad7d9814f8c506eb7b179a5c5b4466a9ec154c3bf1c13efd6ec0d82b02c29af2c690299edc453");

	hex_to_block(key, 32, "40da26dc85fc48a30a52fb7bc8d6db7dd18cb57eb0de5c9b210b5d574dde358b");
	hex_to_block(input, 51, "a166a4e1b63f753ae8f6850c7cf96ff8e83b22eced5dd458af592bb26e3a1d51c85eefc39accd2805095d3288d4b0d0cb996a1");
	kdf(KDF_MODE_DOUBLE_PIPLELINE, KDF_PRF_HMAC, HASH_SHA256, key, 32, input, 51, NULL, 0, NULL, 0, NULL, 0, output, 256);
	status += CHECK_BLOCK(
		output, 256,
		"4d515afd94a115e504ed265dbbe019f1405b4b7ab351e6d496b6b9c15ae7601905eaa123b80c9855fdd458f9871f7ec2d16e05bf8991f8165c9faf916d2c62bcfb"
		"34f0638a2f8c95a5b4b720123719988c5b6fd436858f3df65c4e22fec179cd065ea5cb8551c4582f65ff4f7eae9a3fda752ae862812016aa76343c5b6040d921f1"
		"4f772d2fa9dba65094b244e770965629829dd14a9af537e80ca2122eb71e9b4b1c8e25dfe3b53155d969e596095675ca8dc67c12e11e7d950f219cad5e0bef3d66"
		"68becac52140b9c153897466331ddaedac6d0ae68672e99cae96f6a021686d4fc2f1c9febacf8bc9005e4afb9a5d24a15aa2d7afe1adcad43dc346b09d");

	hex_to_block(key, 32, "9306645e6b3182a66b1cca905480b7ffa8d60467a52c12202476a54287a45bc0");
	hex_to_block(input, 51, "0fc1704af3daaa5942025495c22a710ed64bba03d71f0f89ee2b37552a073797d639a8fda73ee616332f5a54e51359ea578382");
	kdf(KDF_MODE_DOUBLE_PIPLELINE, KDF_PRF_HMAC, HASH_SHA256, key, 32, input, 51, NULL, 0, NULL, 0, NULL, 0, output, 70);
	status += CHECK_BLOCK(output, 70,
						  "a0a718541e7722e8a62b7946ea0244d1b6f3f1dc9213a880cc1c777ead8814b51b687777258e32fe9f0e85854271d9cb029026c3c7eb9201"
						  "36005634b4e1c09acffa969cd952");

	return status;
}

int main()
{
	return kdf_counter_test_suite() + kdf_feedback_test_suite() + kdf_double_pipeline_test_suite();
}
