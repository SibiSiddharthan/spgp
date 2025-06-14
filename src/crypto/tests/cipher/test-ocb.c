/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <test.h>
#include <cipher.h>


// Refer RFC 7253 : The OCB Authenticated-Encryption Algorithm, Appendix A for test vectors

int32_t aes128_ocb_suite(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[16];
	byte_t nonce[16];
	byte_t tag[16];
	byte_t associated_data[64];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221100");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, NULL, 0, NULL, 0, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "785407bfffc8ad9edcc5520ac9111ee6");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 0, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "785407bfffc8ad9edcc5520ac9111ee6");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221101");
	hex_to_block(associated_data, 8, "0001020304050607");
	hex_to_block(plaintext, 8, "0001020304050607");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 8, plaintext, 8, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 8);
	status += CHECK_BLOCK(ciphertext, 8, "6820b3657b6f615a");
	status += CHECK_BLOCK(tag, 16, "5725bda0d3b4eb3a257c9af1f8f03009");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 8, ciphertext, 8, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 8);
	status += CHECK_BLOCK(plaintext, 8, "0001020304050607");
	status += CHECK_BLOCK(tag, 16, "5725bda0d3b4eb3a257c9af1f8f03009");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221102");
	hex_to_block(associated_data, 8, "0001020304050607");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 8, NULL, 0, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "81017f8203f081277152fade694a0a00");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 8, ciphertext, 0, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "81017f8203f081277152fade694a0a00");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221103");
	hex_to_block(plaintext, 8, "0001020304050607");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 8, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 8);
	status += CHECK_BLOCK(ciphertext, 8, "45dd69f8f5aae724");
	status += CHECK_BLOCK(tag, 16, "14054cd1f35d82760b2cd00d2f99bfa9");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 8, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 8);
	status += CHECK_BLOCK(plaintext, 8, "0001020304050607");
	status += CHECK_BLOCK(tag, 16, "14054cd1f35d82760b2cd00d2f99bfa9");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221104");
	hex_to_block(associated_data, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(plaintext, 16, "000102030405060708090a0b0c0d0e0f");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 16, plaintext, 16, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "571d535b60b277188be5147170a9a22c");
	status += CHECK_BLOCK(tag, 16, "3ad7a4ff3835b8c5701c1ccec8fc3358");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 16, ciphertext, 16, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "000102030405060708090a0b0c0d0e0f");
	status += CHECK_BLOCK(tag, 16, "3ad7a4ff3835b8c5701c1ccec8fc3358");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221105");
	hex_to_block(associated_data, 16, "000102030405060708090a0b0c0d0e0f");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 16, NULL, 0, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "8cf761b6902ef764462ad86498ca6b97");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 16, ciphertext, 0, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "8cf761b6902ef764462ad86498ca6b97");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221106");
	hex_to_block(plaintext, 16, "000102030405060708090a0b0c0d0e0f");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 16, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "5ce88ec2e0692706a915c00aeb8b2396");
	status += CHECK_BLOCK(tag, 16, "f40e1c743f52436bdf06d8fa1eca343d");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 16, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "000102030405060708090a0b0c0d0e0f");
	status += CHECK_BLOCK(tag, 16, "f40e1c743f52436bdf06d8fa1eca343d");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221107");
	hex_to_block(associated_data, 24, "000102030405060708090a0b0c0d0e0f1011121314151617");
	hex_to_block(plaintext, 24, "000102030405060708090a0b0c0d0e0f1011121314151617");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 24, plaintext, 24, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(ciphertext, 24, "1ca2207308c87c010756104d8840ce1952f09673a448a122");
	status += CHECK_BLOCK(tag, 16, "c92c62241051f57356d7f3c90bb0e07f");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 24, ciphertext, 24, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(plaintext, 24, "000102030405060708090a0b0c0d0e0f1011121314151617");
	status += CHECK_BLOCK(tag, 16, "c92c62241051f57356d7f3c90bb0e07f");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221108");
	hex_to_block(associated_data, 24, "000102030405060708090a0b0c0d0e0f1011121314151617");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 24, NULL, 0, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "6dc225a071fc1b9f7c69f93b0f1e10de");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 24, ciphertext, 0, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "6dc225a071fc1b9f7c69f93b0f1e10de");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa99887766554433221109");
	hex_to_block(plaintext, 24, "000102030405060708090a0b0c0d0e0f1011121314151617");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 24, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(ciphertext, 24, "221bd0de7fa6fe993eccd769460a0af2d6cded0c395b1c3c");
	status += CHECK_BLOCK(tag, 16, "e725f32494b9f914d85c0b1eb38357ff");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 24, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 24);
	status += CHECK_BLOCK(plaintext, 24, "000102030405060708090a0b0c0d0e0f1011121314151617");
	status += CHECK_BLOCK(tag, 16, "e725f32494b9f914d85c0b1eb38357ff");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa9988776655443322110a");
	hex_to_block(associated_data, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	hex_to_block(plaintext, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 32, plaintext, 32, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(ciphertext, 32, "bd6f6c496201c69296c11efd138a467abd3c707924b964deaffc40319af5a485");
	status += CHECK_BLOCK(tag, 16, "40fbba186c5553c68ad9f592a79a4240");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 32, ciphertext, 32, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(plaintext, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	status += CHECK_BLOCK(tag, 16, "40fbba186c5553c68ad9f592a79a4240");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa9988776655443322110b");
	hex_to_block(associated_data, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 32, NULL, 0, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "fe80690bee8a485d11f32965bc9d2a32");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 32, ciphertext, 0, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "fe80690bee8a485d11f32965bc9d2a32");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa9988776655443322110c");
	hex_to_block(plaintext, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 32, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(ciphertext, 32, "2942bfc773bda23cabc6acfd9bfd5835bd300f0973792ef46040c53f1432bcdf");
	status += CHECK_BLOCK(tag, 16, "b5e1dde3bc18a5f840b52e653444d5df");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 32, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 32);
	status += CHECK_BLOCK(plaintext, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	status += CHECK_BLOCK(tag, 16, "b5e1dde3bc18a5f840b52e653444d5df");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa9988776655443322110d");
	hex_to_block(associated_data, 40, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
	hex_to_block(plaintext, 40, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 40, plaintext, 40, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 40);
	status += CHECK_BLOCK(ciphertext, 40, "d5ca91748410c1751ff8a2f618255b68a0a12e093ff454606e59f9c1d0ddc54b65e8628e568bad7a");
	status += CHECK_BLOCK(tag, 16, "ed07ba06a4a69483a7035490c5769e60");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 40, ciphertext, 40, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 40);
	status += CHECK_BLOCK(plaintext, 40, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
	status += CHECK_BLOCK(tag, 16, "ed07ba06a4a69483a7035490c5769e60");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa9988776655443322110e");
	hex_to_block(associated_data, 40, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 40, NULL, 0, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "c5cd9d1850c141e358649994ee701b68");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 40, ciphertext, 0, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "c5cd9d1850c141e358649994ee701b68");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "000102030405060708090a0b0c0d0e0f");
	hex_to_block(nonce, 12, "bbaa9988776655443322110f");
	hex_to_block(plaintext, 40, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, NULL, 0, plaintext, 40, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 40);
	status += CHECK_BLOCK(ciphertext, 40, "4412923493c57d5de0d700f753cce0d1d2d95060122e9f15a5ddbfc5787e50b5cc55ee507bcb084e");
	status += CHECK_BLOCK(tag, 16, "479ad363ac366b95a98ca5f3000b1479");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, NULL, 0, ciphertext, 40, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 40);
	status += CHECK_BLOCK(plaintext, 40, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
	status += CHECK_BLOCK(tag, 16, "479ad363ac366b95a98ca5f3000b1479");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "0f0e0d0c0b0a09080706050403020100");
	hex_to_block(nonce, 12, "bbaa9988776655443322110d");
	hex_to_block(associated_data, 40, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
	hex_to_block(plaintext, 40, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
	memset(tag, 0, 16);

	result = aes128_ocb_encrypt(key, 16, nonce, 12, associated_data, 40, plaintext, 40, ciphertext, 64, tag, 12);
	status += CHECK_VALUE(result, 40);
	status += CHECK_BLOCK(ciphertext, 40, "1792a4e31e0755fb03e31b22116e6c2ddf9efd6e33d536f1a0124b0a55bae884ed93481529c76b6a");
	status += CHECK_BLOCK(tag, 12, "d0c515f4d1cdd4fdac4f02aa");

	memset(plaintext, 0, 64);
	memset(tag, 0, 16);

	result = aes128_ocb_decrypt(key, 16, nonce, 12, associated_data, 40, ciphertext, 40, plaintext, 64, tag, 12);
	status += CHECK_VALUE(result, 40);
	status += CHECK_BLOCK(plaintext, 40, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
	status += CHECK_BLOCK(tag, 12, "d0c515f4d1cdd4fdac4f02aa");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_ocb_suite();
}
