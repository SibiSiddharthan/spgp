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

int32_t aes128_cbc_test_suite(void)
{
	int32_t status = 0;
	byte_t key[16];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "1f8e4973953f3fb0bd6b16662e9a3c17");
	hex_to_block(iv, 16, "2fe2b333ceda8f98f4a99b40d2cd34a8");
	hex_to_block(plaintext, 16, "45cf12964fc824ab76616ae2f4bf0822");
	aes128_cbc_encrypt(key, 16, iv, 16, plaintext, 16, ciphertext, 16, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 16, "0f61c4d44c5147c03c195ad7e2cc12b2");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "2c14413751c31e2730570ba3361c786b");
	hex_to_block(iv, 16, "1dbbeb2f19abb448af849796244a19d7");
	hex_to_block(plaintext, 160,
				 "40d930f9a05334d9816fe204999c3f82a03f6a0457a8c475c94553d1d116693adc618049f0a769a2eed6a6cb14c0143ec5cccdbc8dec4ce560cfd2062"
				 "25709326d4de7948e54d603d01b12d7fed752fb23f1aa4494fbb00130e9ded4e77e37c079042d828040c325b1a5efd15fc842e44014ca4374bf38f3c3"
				 "fc3ee327733b0c8aee1abcd055772f18dc04603f7b2c1ea69ff662361f2be0a171bbdcea1e5d3f");
	aes128_cbc_encrypt(key, 16, iv, 16, plaintext, 160, ciphertext, 160, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 160,
						  "6be8a12800455a320538853e0cba31bd2d80ea0c85164a4c5c261ae485417d93effe2ebc0d0a0b51d6ea18633d210cf63c0c4ddbc27607f2"
						  "e81ed9113191ef86d56f3b99be6c415a4150299fb846ce7160b40b63baf1179d19275a2e83698376d28b92548c68e06e6d994e2c1501ed29"
						  "7014e702cdefee2f656447706009614d801de1caaf73f8b7fa56cf1ba94b631933bbe577624380850f117435a0355b2b");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "6a7082cf8cda13eff48c8158dda206ae");
	hex_to_block(iv, 16, "bd4172934078c2011cb1f31cffaf486e");
	hex_to_block(ciphertext, 16, "f8eb31b31e374e960030cd1cadb0ef0c");
	aes128_cbc_decrypt(key, 16, iv, 16, ciphertext, 16, plaintext, 16, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 16, "940bc76d61e2c49dddd5df7f37fcf105");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "97a1025529b9925e25bbe78770ca2f99");
	hex_to_block(iv, 16, "d4b4eab92aa9637e87d366384ed6915c");
	hex_to_block(ciphertext, 160,
				 "22cdc3306fcd4d31ccd32720cbb61bad28d855670657c48c7b88c31f4fa1f93c01b57da90be63ead67d6a325525e6ed45083e6fb70a53529d1fa0f556"
				 "53b942af59d78a2660361d63a7290155ac5c43312a25b235dacbbc863faf00940c99624076dfa44068e7c554c9038176953e571751dfc0954d41d1137"
				 "71b06466b1c8d13e0d4cb675ed58d1a619e1540970983781dc11d2dd8525ab5745958d615defda");
	aes128_cbc_decrypt(key, 16, iv, 16, ciphertext, 160, plaintext, 160, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 160,
						  "e8b89150d8438bf5b17449d6ed26bd72127e10e4aa57cad85283e8359e089208e84921649f5b60ea21f7867cbc9620560c4c6238db021216"
						  "db453c9943f1f1a60546173daef2557c3cdd855031b353d4bf176f28439e48785c37d38f270aa4a6faad2baabcb0c0b2d1dd5322937498ce"
						  "803ba1148440a52e227ddba4872fe4d81d2d76a939d24755adb8a7b8452ceed2d179e1a5848f316f5c016300a390bfa7");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes192_cbc_test_suite(void)
{
	int32_t status = 0;
	byte_t key[24];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "ba75f4d1d9d7cf7f551445d56cc1a8ab2a078e15e049dc2c");
	hex_to_block(iv, 16, "531ce78176401666aa30db94ec4a30eb");
	hex_to_block(plaintext, 16, "c51fc276774dad94bcdc1d2891ec8668");
	aes192_cbc_encrypt(key, 24, iv, 16, plaintext, 16, ciphertext, 16, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 16, "70dd95a14ee975e239df36ff4aee1d5d");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "162ad50ee64a0702aa551f571dedc16b2c1b6a1e4d4b5eee");
	hex_to_block(iv, 16, "24408038161a2ccae07b029bb66355c1");
	hex_to_block(plaintext, 160,
				 "be8abf00901363987a82cc77d0ec91697ba3857f9e4f84bd79406c138d02698f003276d0449120bef4578d78fecabe8e070e11710b3f0a2744bd52434"
				 "ec70015884c181ebdfd51c604a71c52e4c0e110bc408cd462b248a80b8a8ac06bb952ac1d7faed144807f1a731b7febcaf7835762defe92eccfc7a994"
				 "4e1c702cffe6bc86733ed321423121085ac02df8962bcbc1937092eebf0e90a8b20e3dd8c244ae");
	aes192_cbc_encrypt(key, 24, iv, 16, plaintext, 160, ciphertext, 160, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 160,
						  "c82cf2c476dea8cb6a6e607a40d2f0391be82ea9ec84a537a6820f9afb997b76397d005424faa6a74dc4e8c7aa4a8900690f894b6d1dca80"
						  "675393d2243adac762f159301e357e98b724762310cd5a7bafe1c2a030dba46fd93a9fdb89cc132ca9c17dc72031ec6822ee5a9d99dbca66"
						  "c784c01b0885cbb62e29d97801927ec415a5d215158d325f9ee689437ad1b7684ad33c0d92739451ac87f39ff8c31b84");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "8e2740fba157aef2422e442312d15c14d312553684fcdc15");
	hex_to_block(iv, 16, "324015878cdc82bfae59a2dc1ff34ea6");
	hex_to_block(ciphertext, 16, "39a9b42de19e512ab7f3043564c3515a");
	aes192_cbc_decrypt(key, 24, iv, 16, ciphertext, 16, plaintext, 16, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 16, "aa41179d880e6fe3b14818d6e4a62eb5");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "509baf46fb9de34281dafcc3db79593bffa8426904302688");
	hex_to_block(iv, 16, "d6d86e0c82dd8788f4147a26f9a71c74");
	hex_to_block(ciphertext, 160,
				 "6928299c52b4f047926f8a541529da2d6bbaa399143ced8efb77ab47409d9a953a386c7abd6026f49831c717627c2a5e77bd2d433d4d130dacd927ea0"
				 "d13a23d01a7cf39c6716dafb6ed552410ef5d27fb947be2c8782eee7829196c7edcf151c65f9a01f54f8d20f38b7da4a7e83a2f0127d59d3e2405d867"
				 "4fc9f41b604f788f4715f9d3624eee57f387bfadd18a1f905e839c26b8617482347fab6d08845a");
	aes192_cbc_decrypt(key, 24, iv, 16, ciphertext, 160, plaintext, 160, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 160,
						  "67d2dda6da26e21307973400600725727ae81415511772f4a09ad9903bcf90cc2c0dac58ba559a0109c54a9d6117b15bb574ca473e848047"
						  "e9a54ee4abde76aff9849c44109d161f46442e1610d8b015cf36a010ed8efa3207fdfc8fcc548f145c027e44c5b0ec35c9886f4b9d6513a5"
						  "bc10d0ea6bbbc26f54b183bcae27fb799d8872ff748fc459d55cfa255aae29d71b076d9b44c14d5ceba9332a763d9c94");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes256_cbc_test_suite(void)
{
	int32_t status = 0;
	byte_t key[32];
	byte_t iv[16];
	byte_t plaintext[256];
	byte_t ciphertext[256];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907");
	hex_to_block(iv, 16, "851e8764776e6796aab722dbb644ace8");
	hex_to_block(plaintext, 16, "6282b8c05c5c1530b97d4816ca434762");
	aes256_cbc_encrypt(key, 32, iv, 16, plaintext, 16, ciphertext, 16, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 16, "6acc04142e100a65f51b97adf5172c41");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "48be597e632c16772324c8d3fa1d9c5a9ecd010f14ec5d110d3bfec376c5532b");
	hex_to_block(iv, 16, "d6d581b8cf04ebd3b6eaa1b53f047ee1");
	hex_to_block(plaintext, 160,
				 "0c63d413d3864570e70bb6618bf8a4b9585586688c32bba0a5ecc1362fada74ada32c52acfd1aa7444ba567b4e7daaecf7cc1cb29182af164ae5232b0"
				 "02868695635599807a9a7f07a1f137e97b1e1c9dabc89b6a5e4afa9db5855edaa575056a8f4f8242216242bb0c256310d9d329826ac353d715fa39f80"
				 "cec144d6424558f9f70b98c920096e0f2c855d594885a00625880e9dfb734163cecef72cf030b8");
	aes256_cbc_encrypt(key, 32, iv, 16, plaintext, 160, ciphertext, 160, PADDING_NONE);

	status += CHECK_BLOCK(ciphertext, 160,
						  "fc5873e50de8faf4c6b84ba707b0854e9db9ab2e9f7d707fbba338c6843a18fc6facebaf663d26296fb329b4d26f18494c79e09e779647f9"
						  "bafa87489630d79f4301610c2300c19dbf3148b7cac8c4f4944102754f332e92b6f7c5e75bc6179eb877a078d4719009021744c14f13fd2a"
						  "55a2b9c44d18000685a845a4f632c7c56a77306efa66a24d05d088dcd7c13fe24fc447275965db9e4d37fbc9304448cd");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "43e953b2aea08a3ad52d182f58c72b9c60fbe4a9ca46a3cb89e3863845e22c9e");
	hex_to_block(iv, 16, "ddbbb0173f1e2deb2394a62aa2a0240e");
	hex_to_block(ciphertext, 16, "d51d19ded5ca4ae14b2b20b027ffb020");
	aes256_cbc_decrypt(key, 32, iv, 16, ciphertext, 16, plaintext, 16, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 16, "07270d0e63aa36daed8c6ade13ac1af1");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "87725bd43a45608814180773f0e7ab95a3c859d83a2130e884190e44d14c6996");
	hex_to_block(iv, 16, "e49651988ebbb72eb8bb80bb9abbca34");
	hex_to_block(ciphertext, 160,
				 "5b97a9d423f4b97413f388d9a341e727bb339f8e18a3fac2f2fb85abdc8f135deb30054a1afdc9b6ed7da16c55eba6b0d4d10c74e1d9a7cf8edfaeaa6"
				 "84ac0bd9f9d24ba674955c79dc6be32aee1c260b558ff07e3a4d49d24162011ff254db8be078e8ad07e648e6bf5679376cb4321a5ef01afe6ad8816fc"
				 "c7634669c8c4389295c9241e45fff39f3225f7745032daeebe99d4b19bcb215d1bfdb36eda2c24");
	aes256_cbc_decrypt(key, 32, iv, 16, ciphertext, 160, plaintext, 160, PADDING_NONE);

	status += CHECK_BLOCK(plaintext, 160,
						  "bfe5c6354b7a3ff3e192e05775b9b75807de12e38a626b8bf0e12d5fff78e4f1775aa7d792d885162e66d88930f9c3b2cdf8654f56972504"
						  "803190386270f0aa43645db187af41fcea639b1f8026ccdd0c23e0de37094a8b941ecb7602998a4b2604e69fc04219585d854600e0ad6f99"
						  "a53b2504043c08b1c3e214d17cde053cbdf91daa999ed5b47c37983ba3ee254bc5c793837daaa8c85cfc12f7f54f699f");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_cbc_test_suite() + aes192_cbc_test_suite() + aes256_cbc_test_suite();
}
