/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <cipher.h>

#include <test.h>

// Test vectors taken from NIST

int32_t aes128_ecb_test_suite(void)
{
	int32_t status = 0;
	byte_t key[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "edfdb257cb37cdf182c5455b0c0efebb");
	hex_to_block(plaintext, 16, "1695fe475421cace3557daca01f445ff");
	aes128_ecb_encrypt(key, 16, plaintext, 16, ciphertext, 16, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 16, "7888beae6e7a426332a7eaa2f808e637");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "ebea9c6a82213a00ac1d22faea22116f");
	hex_to_block(plaintext, 160,
				 "451f45663b44fd005f3c288ae57b383883f02d9ad3dc1715f9e3d6948564257b9b06d7dd51935fee580a96bbdfefb918b4e6b1daac809847465578cb8"
				 "b5356ed38556f801ff7c11ecba9cdd263039c15d05900fc228e1caf302d261d7fb56cee663595b96f192a78ff4455393a5fe8162170a066fdaeac3501"
				 "9469f22b3470686bced2f007a1a2e43e01b4562caaa502ed541b8205874ec1ffb1c8b255766942");
	aes128_ecb_encrypt(key, 16, plaintext, 160, ciphertext, 160, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 160,
						  "01043053f832ef9b911ed387ba577451e30d51d4b6b11f319d4cd539d067b7f4f9b4f41f7f3d4e920c57cbe2b5e1885aa66203ae493e93a1"
						  "df63793a9563c176bc6775dd09cc9161e278a01beb8fd8a19200326bd95abc5f716768e34f90b50523d30fdabb103a3bc020afbbb0cb3bd2"
						  "ad512a6fea79f8d64cef347458dec48be89451cb0b807d73593f273d9fc521b789a77524404f43e00f20b3b77b938b1a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "54b760dd2968f079ac1d5dd20626445d");
	hex_to_block(ciphertext, 16, "065bd5a9540d22d5d7b0f75d66cb8b30");
	aes128_ecb_decrypt(key, 16, ciphertext, 16, plaintext, 16, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 16, "46f2c98932349c338e9d67f744a1c988");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "44f0ee626d0446e0a3924cfb078944bb");
	hex_to_block(ciphertext, 160,
				 "931b2f5f3a5820d53a6beaaa6431083a3488f4eb03b0f5b57ef838e1579623103bd6e6800377538b2e51ef708f3c4956432e8a8ee6a34e190642b26ad"
				 "8bdae6c2af9a6c7996f3b6004d2671e41f1c9f40ee03d1c4a52b0a0654a331f15f34dce4acb96bd6507815ca4347a3de11a311b7de5351c9787c45381"
				 "58e28974ffa83d8296dfe9cd09cd87f7bf4f54d97d28d4788799163408323943b3e72f5eab66c1");
	aes128_ecb_decrypt(key, 16, ciphertext, 160, plaintext, 160, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 160,
						  "9c29eecb2de04254fafb896a994102d1da30ddb49d82728eb23dbd029901e9b75b3d0aee03f7a05f6c852d8fada0b5c28e8c9aed334fad11"
						  "829df3dfadc5c2e471eb41af9e48a8a465e03d5ebdb0216915081f3b5a0ebb2308dfc2d28e5a8ba3f32adae4c3575921bc657b63d46ba5a6"
						  "18880ee9ad8af3fba5643a5026facd7d667ce599327f936cdda7e1bb742a33a019990b76be648a6ec725daed540ed9e7");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes192_ecb_test_suite(void)
{
	int32_t status = 0;
	byte_t key[24];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "61396c530cc1749a5bab6fbcf906fe672d0c4ab201af4554");
	hex_to_block(plaintext, 16, "60bcdb9416bac08d7fd0d780353740a5");
	aes192_ecb_encrypt(key, 24, plaintext, 16, ciphertext, 16, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 16, "24f40c4eecd9c49825000fcb4972647a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "4f41fa4d4a25100b586551828373bcca5540c68e9bf84562");
	hex_to_block(plaintext, 160,
				 "7c727bd3e7048e7a8995b7b1169ae4b5a55e854bb4f7a9576d7863ab2868731d307322dcca606e047343676f6af4d9cf6ebf2bf9c95d87848d233c931"
				 "e7a60eff08fb959924cde1eec8699ebc57890e3887024ef47c89a550018788d1faa3250452e06f148af25f07bc613cd2f0e501a79d738d4361f28f34d"
				 "bee24034e03367b6b8d34df3738ca3a86b9ebcb09e639bcb5e2f519f4a7a86fc7c41556404a95d");
	aes192_ecb_encrypt(key, 24, plaintext, 160, ciphertext, 160, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 160,
						  "922812ad5feacdf11fe7fdae96300149419e31cff54061b3c5ed27fdb8b50c9c0932b522a6c04e482499b011ef3c3e9dc56a1a61cfeb78b3"
						  "4032d26dbdc3cac51a3279bc934b9bce2d9c19bf858235613ba784e48e292d22c6b5a28e1d1bb860524fb7b5f9b3d9a5f4da66e340585bd2"
						  "496fe6d6942db8d05d716fec03b17d19abb58b33332e24beaec7995d69525364fe139aa1fd62054668c58f23f1f94cfd");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "f2d2b82280c2592ecfbcf500ae647078c9c57624cde9bf6c");
	hex_to_block(ciphertext, 16, "21c8229a4dceaf533fe4e96eced482a6");
	aes192_ecb_decrypt(key, 24, ciphertext, 16, plaintext, 16, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 16, "49aabe67da5322b6e11d63b78b5a0e15");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "9cc24ea1f1959d9a972e7182ef3b4e22a97a87d0da7ff64b");
	hex_to_block(ciphertext, 160,
				 "952f4546a8bf7166964917ece01bda3c6857e427cef5da0ff90b0e4bf44cf7ccfccfdf01d713dcf9673f01c87eaed52bf4aa046ff778558ea396dc9cd"
				 "240716136386148a5c76378b3ffcd40864407b8e60b40a594e0619eddae3f6d6e3b15b86af231e1bae5ed2aa512e11da0e5572b67ffff934c36e585cf"
				 "dd9f877045cb19c183b994bf74645862ffa726739aadcb9e10aaffc881c88ca3aa65b37f667bcb");
	aes192_ecb_decrypt(key, 24, ciphertext, 160, plaintext, 160, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 160,
						  "b8bb5ce53a15aa6dfdf2cb61bc8e3617d1d0fefe9ba5d175550470e32397f6f3b3e65b43bded2b21e5c181d3c4c4c526c41ceab044289508"
						  "458048b63352dfc379de373fd19a2c900c43524b75949e677cceda866f7f2bcc4844ef2e5dac5b804b4045e657c8156d1dcdb43cbf2f5e00"
						  "a4f9255e3be2439436c4d0449a8d2c4c1a56bece98ea0fd68abaf12398039994aebffc692b9000e580479b4f4b28b5fe");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes256_ecb_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "cc22da787f375711c76302bef0979d8eddf842829c2b99ef3dd04e23e54cc24b");
	hex_to_block(plaintext, 16, "ccc62c6b0a09a671d64456818db29a4d");
	aes256_ecb_encrypt(key, 32, plaintext, 16, ciphertext, 16, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 16, "df8634ca02b13a125b786e1dce90658b");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "44a2b5a7453e49f38261904f21ac797641d1bcd8ddedd293f319449fe63b2948");
	hex_to_block(plaintext, 160,
				 "c91b8a7b9c511784b6a37f73b290516bb9ef1e8df68d89bf49169eac4039650c4307b6260e9c4e93650223440252f5c7d31c26c56209cbd095bf035b9"
				 "705880a1628832daf9da587a6e77353dbbce189f963235df160c008a753e8ccea1e0732aa469a97659c42e6e31c16a723153e39958abe5b8ad88ff2e8"
				 "9af40622ca0b0d6729a26c1ae04d3b8367b548c4a6335f0e5a9ec914bb6113c05cd0112552bc21");
	aes256_ecb_encrypt(key, 32, plaintext, 160, ciphertext, 160, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 160,
						  "05d51af0e2b61e2c06cb1e843fee3172825e63b5d1ce8183b7e1db6268db5aa726521f46e948028aa443af9ebd8b7c6baf958067ab0d4a8a"
						  "c530ecbb68cdfc3eb93034a428eb7e8f6a3813cea6189068dfecfa268b7ecd5987f8cb2732c6882bbec8f716bac254d72269230aec5dc7f5"
						  "a6b866fd305242552d400f5b0404f19cbfe7291fab690ecfe6018c4309fc639d1b65fcb65e643edb0ad1f09cfe9cee4a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "a81fd6ca56683d0f5445659dde4d995dc65f4bce208963053e28d7f2df517ce4");
	hex_to_block(ciphertext, 16, "4154c0be71072945d8156f5f046d198d");
	aes256_ecb_decrypt(key, 32, ciphertext, 16, plaintext, 16, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 16, "8b2b1b22f733ac09d1196d6be6a87a72");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "c4a71e055a7254dda360693fe1be49f10faa6731c36dbaa6590b05974e185c5b");
	hex_to_block(ciphertext, 160,
				 "2c487fa96f4090c56aa1b5be81918a934c9492878fb0cd686dcf8d17d86485454c51237bbd09205dcef1552f430dd098b9d827a694730c133a0222c77"
				 "f540f9d5fc2d36af359583c9e3b49df884228a64de79b67f66207c8281360b99b214042ce61367ff97960e944453cd63679bb44708897d29bc5e70f9f"
				 "c8f1f715143fbb00f7f5c1b7b161ec26d8d41d36fab0fa8a85c3ee6ce4d37007eb7a89d6753590");
	aes256_ecb_decrypt(key, 32, ciphertext, 160, plaintext, 160, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 160,
						  "31fd5a307e279b2f34581e2c432379df8eccbaf79532938916711cd377540b9045373e47f2214b8f876040af733f6c9d8f03a7c58f8714d2"
						  "fbb4c14af59c75b483adc718946ee907a18286cc4efd206789064b6f1b195f0d0d234468e4f00e6f1cad5cd3b9c0a643b3c0dd09280ff2e2"
						  "a5929183409384dd72dc94e39687ea2b623d5d776700bd8b36e6130ffde966f134c4b1f35f29c5cc4a03297e1ccc9539");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_ecb_test_suite() + aes192_ecb_test_suite() + aes256_ecb_test_suite();
}
