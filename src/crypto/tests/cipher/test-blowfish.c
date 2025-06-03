/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <test.h>
#include <blowfish.h>

// See RFC 2144: The CAST-128 Encryption Algorithm, Appendix B for test vectors

int32_t blowfish64_test_suite(void)
{
	int32_t status = 0;
	byte_t secret[BLOWFISH64_KEY_SIZE];
	byte_t plaintext[BLOWFISH_BLOCK_SIZE];
	byte_t ciphertext[BLOWFISH_BLOCK_SIZE];

	blowfish_key key = {0};

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "0000000000000000");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0000000000000000");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "4ef997456198dd78");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "ffffffffffffffff");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "ffffffffffffffff");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "51866fd5b85ecb8a");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "ffffffffffffffff");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "3000000000000000");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "1000000000000001");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "7d856f9a613063f2");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "1000000000000001");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "1111111111111111");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "1111111111111111");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "2466dd878b963c9d");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "1111111111111111");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "0123456789abcdef");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "1111111111111111");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "61f9c3802281b096");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "1111111111111111");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "1111111111111111");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "7d0cc630afda1ec7");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "0000000000000000");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0000000000000000");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "4ef997456198dd78");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "fedcba9876543210");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "0aceab0fc6a0a28d");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "7ca110454a1a6e57");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "01a1d6d039776742");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "59c68245eb05282b");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "01a1d6d039776742");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "0131d9619dc1376e");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "5cd54ca83def57da");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "b1b8cc0b250f09a0");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "5cd54ca83def57da");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "07a1133e4a0b2686");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0248d43806f67172");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "1730e5778bea1da4");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0248d43806f67172");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "3849674c2602319e");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "51454b582ddf440a");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "a25e7856cf2651eb");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "51454b582ddf440a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "04b915ba43feb5b6");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "42fd443059577fa2");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "353882b109ce8f1a");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "42fd443059577fa2");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "0113b970fd34f2ce");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "059b5e0851cf143a");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "48f4d0884c379918");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "059b5e0851cf143a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "0170f175468fb5e6");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0756d8e0774761d2");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "432193b78951fc98");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0756d8e0774761d2");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "43297fad38e373fe");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "762514b829bf486a");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "13f04154d69d1ae5");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "762514b829bf486a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "07a7137045da2a16");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "3bdd119049372802");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "2eedda93ffd39c79");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "3bdd119049372802");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "04689104c2fd3b2f");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "26955f6835af609a");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "d887e0393c2da6e3");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "26955f6835af609a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "37d06bb516cb7546");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "164d5e404f275232");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "5f99d04f5b163969");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "164d5e404f275232");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "1f08260d1ac2465e");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "6b056e18759f5cca");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "4a057a3b24d3977b");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "6b056e18759f5cca");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "584023641aba6176");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "004bd6ef09176062");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "452031c1e4fada8e");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "004bd6ef09176062");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "025816164629b007");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "480d39006ee762f2");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "7555ae39f59b87bd");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "480d39006ee762f2");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "49793ebc79b3258f");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "437540c8698f3cfa");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "53c55f9cb49fc019");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "437540c8698f3cfa");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "4fb05e1515ab73a7");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "072d43a077075292");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "7a8e7bfa937e89a3");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "072d43a077075292");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "49e95d6d4ca229bf");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "02fe55778117f12a");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "cf9c5d7a4986adb5");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "02fe55778117f12a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "018310dc409b26d6");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "1d9d5c5018f728c2");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "d1abb290658bc778");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "1d9d5c5018f728c2");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "1c587f1c13924fef");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "305532286d6f295a");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "55cb3774d13ef201");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "305532286d6f295a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "0101010101010101");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "fa34ec4847b268b2");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "1f1f1f1f0e0e0e0e");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "a790795108ea3cae");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "e0fee0fef1fef1fe");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "c39e072d9fac631d");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0123456789abcdef");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "0000000000000000");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "ffffffffffffffff");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "014933e0cdaff6e4");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "ffffffffffffffff");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "ffffffffffffffff");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0000000000000000");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "f21e9a77b71c49bc");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "0123456789abcdef");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "0000000000000000");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "245946885754369a");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "0000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(secret, BLOWFISH64_KEY_SIZE, "fedcba9876543210");
	hex_to_block(plaintext, BLOWFISH_BLOCK_SIZE, "ffffffffffffffff");

	blowfish64_key_init(&key, secret);

	memset(ciphertext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_encrypt_block(&key, plaintext, ciphertext);
	status += CHECK_BLOCK(ciphertext, BLOWFISH_BLOCK_SIZE, "6b5c5a9c5d9e0a5a");

	memset(plaintext, 0, BLOWFISH_BLOCK_SIZE);
	blowfish_decrypt_block(&key, ciphertext, plaintext);
	status += CHECK_BLOCK(plaintext, BLOWFISH_BLOCK_SIZE, "ffffffffffffffff");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return blowfish64_test_suite();
}
