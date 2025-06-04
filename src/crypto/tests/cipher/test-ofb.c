/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <test.h>
#include <cipher.h>


// Test vectors taken from NIST

int32_t aes128_ofb_test_suite(void)
{
	int32_t status = 0;
	byte_t key[16];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "d7d57bd847154af9722a8df096e61a42");
	hex_to_block(iv, 16, "fdde201c91e401d9723868c2a612b77a");
	hex_to_block(plaintext, 16, "81883f22165282ba6a442a8dd2a768d4");
	aes128_ofb_encrypt(key, 16, iv, 16, plaintext, 16, ciphertext, 16);

	status += CHECK_BLOCK(ciphertext, 16, "84cc130b6867623696aa8f523d968ade");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "939aac71e337709855715a57e3a4648f");
	hex_to_block(iv, 16, "493509b56a92f14040eb9b66a188bc57");
	hex_to_block(plaintext, 160,
				 "9c22efddc7de496a916d15d710de374d57478126ed64c9ad7e823e24d19bfc0cfac3dda0d1c292a3a203f35b26ad94deb20f998caf41cbdd4a08eb5d6"
				 "cfb46f4ede4896b0569d72c03ec194941af95c0573cc3fe8f045ba19946b382803248f3dd4f9a454b1a3e8e1af02ea8482d637dac96a68275f4a382d3"
				 "023f9df4892b9032cab9378b1cef5051d6db81226f259d1be4eb23495ac807600536b5b0481754");
	aes128_ofb_encrypt(key, 16, iv, 16, plaintext, 160, ciphertext, 160);

	status += CHECK_BLOCK(ciphertext, 160,
						  "7c0217d4f990342be5a35e2bdd4756ae7f461add633a7b0f5174ee107a7c0c53b1c787cb83e5ddb876e251a23caf7959d952638c2aa28b2b"
						  "08928c9b88e4c0e0fd0d8154690c3638ce692f20905e7263ff359bcc17e3b43d2276ef1fc4c882282f9a453bc03eb29e9c95986318c19150"
						  "acf1bf33270752d32488543f598f8ed4db3ccb990c8bfdf64cae0d1c6011042acda8c2687a758c2ba8080720990be88d");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "8368189d41eaa20d06a3a2d2a91e43f7");
	hex_to_block(iv, 16, "cf04ac0e4733952ba538711f79eef8ca");
	hex_to_block(ciphertext, 16, "7ddda312308993a58e636744a0a38491");
	aes128_ofb_decrypt(key, 16, iv, 16, ciphertext, 16, plaintext, 16);

	status += CHECK_BLOCK(plaintext, 16, "696ca57339840fb3c150e0c111d9e13e");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "e30b4c874c4c4f6e0cf1f8ef58e5d375");
	hex_to_block(iv, 16, "7e26f07f8024343cec35409e71e0cd8c");
	hex_to_block(ciphertext, 160,
				 "5dcaa173ede14fd2d658973926168ff34fd6df9bce3280d40b00c43b80e2979a1e19045fec9afb4cf264516f55100855c3aad17b11bfcf0523b79eb20"
				 "d65941077dd46ec46864e0d79704c2250e72bf8b448a6f0d3130ab10b423d1a09d9ff7a32bf700441ccd27d3223913860c28044ea5766e45a55b93f89"
				 "48a959bd6661421566898e27950f04e726279bcbc990a22c80193ef0ae65196671eb59713240cf");
	aes128_ofb_decrypt(key, 16, iv, 16, ciphertext, 160, plaintext, 160);

	status += CHECK_BLOCK(plaintext, 160,
						  "8ceca4dc346cfd6b15774e082db1a89497b7d85d6b5b7102e77417f7a243fafe17118b7a3bb49d1657cf61b866da395a5b3f349183a53dfa"
						  "11fc0ac053bddff49dd472ee55f5e43a2f8bc785e2bc420300694919ff7bb43feb75a9cac44ece96f679e618db5d7433af12dcc7e0963ff1"
						  "0b45d835f9a8f42627e7f3fd5038932685965ad0e183f5955e671fc2b878dd51051eedaf85310d1e4e8f75f2decf36c7");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes192_ofb_test_suite(void)
{
	int32_t status = 0;
	byte_t key[24];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "2943e3edfa815260a8a697b386ca3ae3eee914f22b3857dc");
	hex_to_block(iv, 16, "c6995f00318c241217cdc82cf2fa43f9");
	hex_to_block(plaintext, 16, "67e2cf5d63334ae03dbda91100ab781b");
	aes192_ofb_encrypt(key, 24, iv, 16, plaintext, 16, ciphertext, 16);

	status += CHECK_BLOCK(ciphertext, 16, "225e8bfb133c4332ba6e95ddb841370d");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "17b0f9915f6b541e1d3fec5b9c5dfe1cb05a9dbc9983b20f");
	hex_to_block(iv, 16, "eaf17cec9714d2e6f266f283618494eb");
	hex_to_block(plaintext, 160,
				 "0d4e7f3f732bf9d8d2d3f648968fe84175d1c7f5ac6d6be48c0539f336c501bfa3512730e7fc0151b63b815f27591420b86cc9759287b6330f31982f7"
				 "a16b99816fd178a61fac2df99e58649800aca9e5d22b87243839eeb959394d1ca8260e56e399674698d042b84b94c2d290bd3636addda1346c7ebb527"
				 "137702ae71bd4db3eced16881d8edd7e9f1d34abc3f718ea84798122bd6538cc9987e9af4b9979");
	aes192_ofb_encrypt(key, 24, iv, 16, plaintext, 160, ciphertext, 160);

	status += CHECK_BLOCK(ciphertext, 160,
						  "05f6ec0f2e2215cc4518750c4c6adb0b4e0b28b0889b33528cc3865a44d8f3680d838ff3da8d57d18df22187a716ad24630645732b7510aa"
						  "77f5e3181f402b72df2543f825ff06ad5993324524a917093867ae5b59ae439697fd53fb9605eed3cc6b5c89fee0b6bdfe62e1444290f3dd"
						  "71ff6aa1b60a8abdbc70b2ae3aee999739d7e6952a18fcf43151b65a5c9504fe3bf166917a264ab0c048cdfc40d4e0bf");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "b57c1f00ef9aa21ede38d0c1addddedadd21dcc7a0773aca");
	hex_to_block(iv, 16, "658b01d8dda573850cb2c27dba2a139e");
	hex_to_block(ciphertext, 16, "09f40f19164302e12043e7c30627b42d");
	aes192_ofb_decrypt(key, 24, iv, 16, ciphertext, 16, plaintext, 16);

	status += CHECK_BLOCK(plaintext, 16, "1bbdad8549babb85efa475bff0307d5e");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "753c1f7f39afd286ff051339c45d57c848850393b4112fe5");
	hex_to_block(iv, 16, "d3ee0d8de5080eda4c26f5a3b9ca8a9f");
	hex_to_block(ciphertext, 160,
				 "a91409fa694a4ad34a9cb1c1534a94979a5beb390083a6a61b4a4436746ba120f37a0f3e97caa9156a8ee410b53e670c703d1d19fcb8887f15d158000"
				 "2fd3c5d0eaaf81c3c26b88737bca3f88820b4540b0dc5d6a42ced0e2e380c29b460a472e4eceb19c0241e33976d170334b6227855120df65fa67e5a4f"
				 "c68938f45b82665c8810bf8c8d832173eb68b821c95a7f35961b0394f0e36b61c4f7b529b77e42");
	aes192_ofb_decrypt(key, 24, iv, 16, ciphertext, 160, plaintext, 160);

	status += CHECK_BLOCK(plaintext, 160,
						  "ad3ccda264343130bf1db3703e27127176fbaa7b6a5da2718783baf9f28fcdd3ed9cd31adcc79427fe4df03f1672a5e55cab0db0f4d434d8"
						  "60340d2fa05bfeb07e924157064a24d0f10e3293f78a2676e3c53734f22d4ea33e89384bd17f4a0f59354179ce48a7d1c1ba35e7f77735f5"
						  "8680f0e89bf9242a4f087322d99e507336a8e9037b6f1bfbe45614abeb2f71516b94caf618851ddcfac7429a2177be40");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes256_ofb_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "6f419b4c683a44d67d234eaa6b57f622f912de657dddb280a14d0cb967ed951f");
	hex_to_block(iv, 16, "19b888800ff1d0116124f79dfae54ffe");
	hex_to_block(plaintext, 16, "3d12989faf41ba75bfa70e2bcc2fa222");
	aes256_ofb_encrypt(key, 32, iv, 16, plaintext, 16, ciphertext, 16);

	status += CHECK_BLOCK(ciphertext, 16, "2d6b005e8d3bc6ea9f62dca36d47aea5");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "1d6fab8e8e49d623cfc8d105f04dcfab60175d7db4fd452ea463b34c56679615");
	hex_to_block(iv, 16, "2aff323645f8aecf9204e7450952264f");
	hex_to_block(plaintext, 160,
				 "581d511bbd441d3531e77a910ad194f40d8a69b63cd6396cef7f37c5265485b21e725fca22c297eca4c341268c8aafd5d007a00e4589b43db584230c3"
				 "193af87a8b9d77db9ec4e29c6d4ab114ad0622f6c3af34fd4ec61b8bd02e60e4be2e5771f7a20fd2ac92b34bea1211cebab954808abcb409005282530"
				 "81e8931d4b0fcbab3ea2121c611654b5b2090d1823306acde391ab22def2cb358791634fd515cc");
	aes256_ofb_encrypt(key, 32, iv, 16, plaintext, 160, ciphertext, 160);

	status += CHECK_BLOCK(ciphertext, 160,
						  "6ca579544f243cb2074feb19edc128faa33635d6eed0c850502669860d7ea66842298154ab455f79db45fd72e0ce88d49210226c489e9c15"
						  "fe09216218707bcb96e1e59aa8d7fcd99728f71a478f9fedc109a111622a63b8e6e736207b37adbf0e6f4990ed76b42434473f90bb8c75ca"
						  "7df47d72dab61fb0c67d265502217c4e590b3536d8d7c7a03a64735e87799423f40b123b8e431e3bba45bf193b6c4af0");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "56c58f5c2141c8ec0327b1a6bb8e13fc8412290f8c7ab272a79845314571e512");
	hex_to_block(iv, 16, "a30b0b95c57e6897b40ce8ddd4209656");
	hex_to_block(ciphertext, 16, "bc2389f583569cfcf89f091aa9a3f2be");
	aes256_ofb_decrypt(key, 32, iv, 16, ciphertext, 16, plaintext, 16);

	status += CHECK_BLOCK(plaintext, 16, "f5639c9ce76e4350ce4758da04570532");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "98a9971e86806ccc3495116fd06dc9d1522fe88060fdddc36e846fd329d24748");
	hex_to_block(iv, 16, "9983ce048f19ef4043054c03aa010bee");
	hex_to_block(ciphertext, 160,
				 "4b0767fec0d4bd07c79c0f5652dafadf10cfce89e3259dea94d39252c640840c28abcbe0efca53dc84b1ef5579f6ef28c213f445220b036fe351d93dc"
				 "ae57e654ac01d39f87213723f0a462d5536b8336dab5c7d2fc728f865756b85f7526144190e0412c3142650616dbde7cde17e887a60ad39f2a1330d82"
				 "09f13233ce5431fd5c297238f8b3ff53a3fb89c84168b04ffa8f7f53e14c36a2d3124d68a27fb5");
	aes256_ofb_decrypt(key, 32, iv, 16, ciphertext, 160, plaintext, 160);

	status += CHECK_BLOCK(plaintext, 160,
						  "00caa233198f51bbf593404f59826997b4ea387385cf744c93cfa00e702e8f16ff5aa7e17a9a6020df0f0de4ea6abb38bcf1d777810a8318"
						  "f69b5e8305f6d727f06f008b4bec2d65cd4c516ca49f62fb2f916f273c45bb722bec78c316f90b5ed5de6ef1d366603ced303c10e33dd5c9"
						  "9eb0f994db5a7867da9b530fc4d0b9ce224c6eab7810359c9733cf933c573611d31fcdf3f1db87cfd17be7f4a470a0b4");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_ofb_test_suite() + aes192_ofb_test_suite() + aes256_ofb_test_suite();
}
