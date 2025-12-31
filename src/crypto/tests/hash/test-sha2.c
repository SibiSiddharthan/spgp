/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <sha.h>
#include <test.h>

int32_t sha224_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[SHA224_HASH_SIZE];

	// See https://www.di-mgt.com.au/sha_testvectors.html for SHA-224 test vectors.

	sha224_hash("", 0, buffer);
	status += CHECK_HASH(buffer, SHA224_HASH_SIZE, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

	// ----------------------------------------------------------------------------------------------------------------

	sha224_hash("abc", 3, buffer);
	status += CHECK_HASH(buffer, SHA224_HASH_SIZE, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");

	// ----------------------------------------------------------------------------------------------------------------

	sha224_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, buffer);
	status += CHECK_HASH(buffer, SHA224_HASH_SIZE, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");

	// ----------------------------------------------------------------------------------------------------------------

	sha224_hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
				buffer);
	status += CHECK_HASH(buffer, SHA224_HASH_SIZE, "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3");

	// ----------------------------------------------------------------------------------------------------------------

	sha224_ctx ctx = {0};

	sha224_init(&ctx);

	for (int32_t i = 0; i < 1000000; i += 50)
	{
		sha224_update(&ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 50);
	}

	sha224_final(&ctx, buffer);

	status += CHECK_HASH(buffer, SHA224_HASH_SIZE, "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67");

	return status;
}

int32_t sha256_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[SHA256_HASH_SIZE];

	// See https://www.di-mgt.com.au/sha_testvectors.html for SHA-256 test vectors.

	sha256_hash("", 0, buffer);
	status += CHECK_HASH(buffer, SHA256_HASH_SIZE, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	// ----------------------------------------------------------------------------------------------------------------

	sha256_hash("abc", 3, buffer);
	status += CHECK_HASH(buffer, SHA256_HASH_SIZE, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	// ----------------------------------------------------------------------------------------------------------------

	sha256_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, buffer);
	status += CHECK_HASH(buffer, SHA256_HASH_SIZE, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

	// ----------------------------------------------------------------------------------------------------------------

	sha256_hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
				buffer);
	status += CHECK_HASH(buffer, SHA256_HASH_SIZE, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

	// ----------------------------------------------------------------------------------------------------------------

	sha256_ctx ctx = {0};

	sha256_init(&ctx);

	for (int32_t i = 0; i < 1000000; i += 50)
	{
		sha256_update(&ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 50);
	}

	sha256_final(&ctx, buffer);

	status += CHECK_HASH(buffer, SHA256_HASH_SIZE, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

	return status;
}

int32_t sha384_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[SHA384_HASH_SIZE];

	// See https://www.di-mgt.com.au/sha_testvectors.html for SHA-384 test vectors.

	sha384_hash("", 0, buffer);
	status += CHECK_HASH(buffer, SHA384_HASH_SIZE,
						 "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");

	// ----------------------------------------------------------------------------------------------------------------

	sha384_hash("abc", 3, buffer);
	status += CHECK_HASH(buffer, SHA384_HASH_SIZE,
						 "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");

	// ----------------------------------------------------------------------------------------------------------------

	sha384_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, buffer);
	status += CHECK_HASH(buffer, SHA384_HASH_SIZE,
						 "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");

	// ----------------------------------------------------------------------------------------------------------------

	sha384_hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
				buffer);
	status += CHECK_HASH(buffer, SHA384_HASH_SIZE,
						 "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");

	// ----------------------------------------------------------------------------------------------------------------

	sha384_ctx ctx = {0};

	sha384_init(&ctx);

	for (int32_t i = 0; i < 1000000; i += 50)
	{
		sha384_update(&ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 50);
	}

	sha384_final(&ctx, buffer);

	status += CHECK_HASH(buffer, SHA384_HASH_SIZE,
						 "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");

	return status;
}

int32_t sha512_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[SHA512_HASH_SIZE];

	// See https://www.di-mgt.com.au/sha_testvectors.html for SHA-512 test vectors.

	sha512_hash("", 0, buffer);
	status += CHECK_HASH(
		buffer, SHA512_HASH_SIZE,
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

	// ----------------------------------------------------------------------------------------------------------------

	sha512_hash("abc", 3, buffer);
	status += CHECK_HASH(
		buffer, SHA512_HASH_SIZE,
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

	// ----------------------------------------------------------------------------------------------------------------

	sha512_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, buffer);
	status += CHECK_HASH(
		buffer, SHA512_HASH_SIZE,
		"204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");

	// ----------------------------------------------------------------------------------------------------------------

	sha512_hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
				buffer);
	status += CHECK_HASH(
		buffer, SHA512_HASH_SIZE,
		"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

	// ----------------------------------------------------------------------------------------------------------------

	sha512_ctx ctx = {0};

	sha512_init(&ctx);

	for (int32_t i = 0; i < 1000000; i += 50)
	{
		sha512_update(&ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 50);
	}

	sha512_final(&ctx, buffer);

	status += CHECK_HASH(
		buffer, SHA512_HASH_SIZE,
		"e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");

	return status;
}

int32_t sha512_224_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[SHA512_224_HASH_SIZE];

	// See https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA_All.pdf
	// for SHA-512/224 test vectors.

	sha512_224_hash("abc", 3, buffer);
	status += CHECK_HASH(buffer, SHA512_224_HASH_SIZE, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");

	// ----------------------------------------------------------------------------------------------------------------

	sha512_224_hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
					buffer);
	status += CHECK_HASH(buffer, SHA512_224_HASH_SIZE, "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9");

	return status;
}

int32_t sha512_256_test_suite(void)
{
	int32_t status = 0;
	byte_t buffer[SHA512_256_HASH_SIZE];

	// See https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA_All.pdf
	// for SHA-512/256 test vectors.

	sha512_256_hash("abc", 3, buffer);
	status += CHECK_HASH(buffer, SHA512_256_HASH_SIZE, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");

	// ----------------------------------------------------------------------------------------------------------------

	sha512_256_hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
					buffer);
	status += CHECK_HASH(buffer, SHA512_256_HASH_SIZE, "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a");

	return status;
}

int main()
{
	return (sha224_test_suite() + sha256_test_suite() + sha384_test_suite() + sha512_test_suite() + sha512_224_test_suite() +
			sha512_256_test_suite());
}
