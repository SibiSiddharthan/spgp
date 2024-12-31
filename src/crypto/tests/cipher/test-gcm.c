/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cipher.h>

#include <test.h>

int32_t aes128_gcm_suite(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[16];
	byte_t iv[64];
	byte_t ad[64];
	byte_t tag[32];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "00000000000000000000000000000000");
	hex_to_block(iv, 12, "000000000000000000000000");

	result = aes128_gcm_encrypt(key, 16, iv, 12, NULL, 0, NULL, 0, ciphertext, 64, tag, 32);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "58e2fccefa7e3061367f1d57a4e7455a");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "00000000000000000000000000000000");
	hex_to_block(iv, 12, "000000000000000000000000");
	hex_to_block(plaintext, 16, "00000000000000000000000000000000");

	result = aes128_gcm_encrypt(key, 16, iv, 12, NULL, 0, plaintext, 16, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "0388dace60b6a392f328c2b971b2fe78");
	status += CHECK_BLOCK(tag, 16, "ab6e47d42cec13bdf53a67b21257bddf");

	memset(plaintext, 0, 64);
	result = aes128_gcm_decrypt(key, 16, iv, 12, NULL, 0, ciphertext, 16, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "00000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "feffe9928665731c6d6a8f9467308308");
	hex_to_block(iv, 12, "cafebabefacedbaddecaf888");
	hex_to_block(
		plaintext, 64,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

	result = aes128_gcm_encrypt(key, 16, iv, 12, NULL, 0, plaintext, 64, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		ciphertext, 64,
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985");
	status += CHECK_BLOCK(tag, 16, "4d5c2af327cd64a62cf35abd2ba6fab4");

	memset(plaintext, 0, 64);
	result = aes128_gcm_decrypt(key, 16, iv, 12, NULL, 0, ciphertext, 64, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		plaintext, 64,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "feffe9928665731c6d6a8f9467308308");
	hex_to_block(iv, 12, "cafebabefacedbaddecaf888");
	hex_to_block(ad, 20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
	hex_to_block(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	result = aes128_gcm_encrypt(key, 16, iv, 12, ad, 20, plaintext, 60, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		ciphertext, 60,
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
	status += CHECK_BLOCK(tag, 16, "5bc94fbc3221a5db94fae95ae7121a47");

	memset(plaintext, 0, 64);
	result = aes128_gcm_decrypt(key, 16, iv, 12, ad, 20, ciphertext, 60, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "feffe9928665731c6d6a8f9467308308");
	hex_to_block(iv, 8, "cafebabefacedbad");
	hex_to_block(ad, 20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
	hex_to_block(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	result = aes128_gcm_encrypt(key, 16, iv, 8, ad, 20, plaintext, 60, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		ciphertext, 60,
		"61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598");
	status += CHECK_BLOCK(tag, 16, "3612d2e79e3b0785561be14aaca2fccb");

	memset(plaintext, 0, 64);
	result = aes128_gcm_decrypt(key, 16, iv, 8, ad, 20, ciphertext, 60, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 16, "feffe9928665731c6d6a8f9467308308");
	hex_to_block(
		iv, 60, "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
	hex_to_block(ad, 20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
	hex_to_block(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	result = aes128_gcm_encrypt(key, 16, iv, 60, ad, 20, plaintext, 60, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		ciphertext, 60,
		"8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5");
	status += CHECK_BLOCK(tag, 16, "619cc5aefffe0bfa462af43c1699d050");

	memset(plaintext, 0, 64);
	result = aes128_gcm_decrypt(key, 16, iv, 60, ad, 20, ciphertext, 60, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes192_gcm_suite(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[24];
	byte_t iv[64];
	byte_t ad[64];
	byte_t tag[32];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "000000000000000000000000000000000000000000000000");
	hex_to_block(iv, 12, "000000000000000000000000");

	result = aes192_gcm_encrypt(key, 24, iv, 12, NULL, 0, NULL, 0, ciphertext, 64, tag, 32);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "cd33b28ac773f74ba00ed1f312572435");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "000000000000000000000000000000000000000000000000");
	hex_to_block(iv, 12, "000000000000000000000000");
	hex_to_block(plaintext, 16, "00000000000000000000000000000000");

	result = aes192_gcm_encrypt(key, 24, iv, 12, NULL, 0, plaintext, 16, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "98e7247c07f0fe411c267e4384b0f600");
	status += CHECK_BLOCK(tag, 16, "2ff58d80033927ab8ef4d4587514f0fb");

	memset(plaintext, 0, 64);
	result = aes192_gcm_decrypt(key, 24, iv, 12, NULL, 0, ciphertext, 16, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "00000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "feffe9928665731c6d6a8f9467308308feffe9928665731c");
	hex_to_block(iv, 12, "cafebabefacedbaddecaf888");
	hex_to_block(
		plaintext, 64,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

	result = aes192_gcm_encrypt(key, 24, iv, 12, NULL, 0, plaintext, 64, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		ciphertext, 64,
		"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256");
	status += CHECK_BLOCK(tag, 16, "9924a7c8587336bfb118024db8674a14");

	memset(plaintext, 0, 64);
	result = aes192_gcm_decrypt(key, 24, iv, 12, NULL, 0, ciphertext, 64, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		plaintext, 64,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "feffe9928665731c6d6a8f9467308308feffe9928665731c");
	hex_to_block(iv, 12, "cafebabefacedbaddecaf888");
	hex_to_block(ad, 20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
	hex_to_block(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	result = aes192_gcm_encrypt(key, 24, iv, 12, ad, 20, plaintext, 60, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		ciphertext, 60,
		"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710");
	status += CHECK_BLOCK(tag, 16, "2519498e80f1478f37ba55bd6d27618c");

	memset(plaintext, 0, 64);
	result = aes192_gcm_decrypt(key, 24, iv, 12, ad, 20, ciphertext, 60, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "feffe9928665731c6d6a8f9467308308feffe9928665731c");
	hex_to_block(iv, 8, "cafebabefacedbad");
	hex_to_block(ad, 20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
	hex_to_block(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	result = aes192_gcm_encrypt(key, 24, iv, 8, ad, 20, plaintext, 60, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		ciphertext, 60,
		"0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7");
	status += CHECK_BLOCK(tag, 16, "65dcc57fcf623a24094fcca40d3533f8");

	memset(plaintext, 0, 64);
	result = aes192_gcm_decrypt(key, 24, iv, 8, ad, 20, ciphertext, 60, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 24, "feffe9928665731c6d6a8f9467308308feffe9928665731c");
	hex_to_block(
		iv, 60, "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
	hex_to_block(ad, 20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
	hex_to_block(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	result = aes192_gcm_encrypt(key, 24, iv, 60, ad, 20, plaintext, 60, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		ciphertext, 60,
		"d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b");
	status += CHECK_BLOCK(tag, 16, "dcf566ff291c25bbb8568fc3d376a6d9");

	memset(plaintext, 0, 64);
	result = aes192_gcm_decrypt(key, 24, iv, 60, ad, 20, ciphertext, 60, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t aes256_gcm_suite(void)
{
	int32_t status = 0;
	uint64_t result = 0;

	byte_t key[32];
	byte_t iv[64];
	byte_t ad[64];
	byte_t tag[32];
	byte_t plaintext[64];
	byte_t ciphertext[64];

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0000000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(iv, 12, "000000000000000000000000");

	result = aes256_gcm_encrypt(key, 32, iv, 12, NULL, 0, NULL, 0, ciphertext, 64, tag, 32);
	status += CHECK_VALUE(result, 0);
	status += CHECK_BLOCK(tag, 16, "530f8afbc74536b9a963b4f1c4cb738b");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "0000000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(iv, 12, "000000000000000000000000");
	hex_to_block(plaintext, 16, "00000000000000000000000000000000");

	result = aes256_gcm_encrypt(key, 32, iv, 12, NULL, 0, plaintext, 16, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(ciphertext, 16, "cea7403d4d606b6e074ec5d3baf39d18");
	status += CHECK_BLOCK(tag, 16, "d0d1c8a799996bf0265b98b5d48ab919");

	memset(plaintext, 0, 64);
	result = aes256_gcm_decrypt(key, 32, iv, 12, NULL, 0, ciphertext, 16, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 16);
	status += CHECK_BLOCK(plaintext, 16, "00000000000000000000000000000000");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
	hex_to_block(iv, 12, "cafebabefacedbaddecaf888");
	hex_to_block(
		plaintext, 64,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

	result = aes256_gcm_encrypt(key, 32, iv, 12, NULL, 0, plaintext, 64, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		ciphertext, 64,
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
	status += CHECK_BLOCK(tag, 16, "b094dac5d93471bdec1a502270e3cc6c");

	memset(plaintext, 0, 64);
	result = aes256_gcm_decrypt(key, 32, iv, 12, NULL, 0, ciphertext, 64, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 64);
	status += CHECK_BLOCK(
		plaintext, 64,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
	hex_to_block(iv, 12, "cafebabefacedbaddecaf888");
	hex_to_block(ad, 20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
	hex_to_block(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	result = aes256_gcm_encrypt(key, 32, iv, 12, ad, 20, plaintext, 60, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		ciphertext, 60,
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
	status += CHECK_BLOCK(tag, 16, "76fc6ece0f4e1768cddf8853bb2d551b");

	memset(plaintext, 0, 64);
	result = aes256_gcm_decrypt(key, 32, iv, 12, ad, 20, ciphertext, 60, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
	hex_to_block(iv, 8, "cafebabefacedbad");
	hex_to_block(ad, 20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
	hex_to_block(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	result = aes256_gcm_encrypt(key, 32, iv, 8, ad, 20, plaintext, 60, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		ciphertext, 60,
		"c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f");
	status += CHECK_BLOCK(tag, 16, "3a337dbf46a792c45e454913fe2ea8f2");

	memset(plaintext, 0, 64);
	result = aes256_gcm_decrypt(key, 32, iv, 8, ad, 20, ciphertext, 60, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	// ------------------------------------------------------------------------------------------------------------------------------------

	hex_to_block(key, 32, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
	hex_to_block(
		iv, 60, "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
	hex_to_block(ad, 20, "feedfacedeadbeeffeedfacedeadbeefabaddad2");
	hex_to_block(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	result = aes256_gcm_encrypt(key, 32, iv, 60, ad, 20, plaintext, 60, ciphertext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		ciphertext, 60,
		"5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f");
	status += CHECK_BLOCK(tag, 16, "a44a8266ee1c8eb0c8b5d4cf5ae9f19a");

	memset(plaintext, 0, 64);
	result = aes256_gcm_decrypt(key, 32, iv, 60, ad, 20, ciphertext, 60, plaintext, 64, tag, 16);
	status += CHECK_VALUE(result, 60);
	status += CHECK_BLOCK(
		plaintext, 60,
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

	// ------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return aes128_gcm_suite() + aes192_gcm_suite() + aes256_gcm_suite();
}
