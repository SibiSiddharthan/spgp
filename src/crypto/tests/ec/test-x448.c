/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <x448.h>
#include <test.h>

// Refer RFC 7748: Elliptic Curves for Security for test vectors

int32_t x448_test_suite(void)
{
	int32_t status = 0;

	byte_t k[X448_KEY_OCTETS] = {0};
	byte_t u[X448_KEY_OCTETS] = {0};
	byte_t v[X448_KEY_OCTETS] = {0};

	// ---------------------------------------------------------------------------------------------------

	memset(k, 0, X448_KEY_OCTETS);
	memset(u, 0, X448_KEY_OCTETS);
	memset(v, 0, X448_KEY_OCTETS);

	hex_to_block(k, X448_KEY_OCTETS,
				 "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
	hex_to_block(u, X448_KEY_OCTETS,
				 "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");

	x448(v, u, k);

	status +=
		CHECK_BLOCK(v, X448_KEY_OCTETS,
					"ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");

	// ---------------------------------------------------------------------------------------------------

	memset(k, 0, X448_KEY_OCTETS);
	memset(u, 0, X448_KEY_OCTETS);
	memset(v, 0, X448_KEY_OCTETS);

	hex_to_block(k, X448_KEY_OCTETS,
				 "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f");
	hex_to_block(u, X448_KEY_OCTETS,
				 "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db");

	x448(v, u, k);

	status +=
		CHECK_BLOCK(v, X448_KEY_OCTETS,
					"884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d");

	// ---------------------------------------------------------------------------------------------------

	return status;
}

int32_t x448_ecdh(void)
{
	int32_t status = 0;

	byte_t alice_private_key[X448_KEY_OCTETS] = {0};
	byte_t alice_public_key[X448_KEY_OCTETS] = {0};

	byte_t bob_private_key[X448_KEY_OCTETS] = {0};
	byte_t bob_public_key[X448_KEY_OCTETS] = {0};

	byte_t alice_shared[X448_KEY_OCTETS] = {0};
	byte_t bob_shared[X448_KEY_OCTETS] = {0};

	byte_t base_point[X448_KEY_OCTETS] = {0};

	hex_to_block(base_point, X448_KEY_OCTETS,
				 "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(alice_private_key, X448_KEY_OCTETS,
				 "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
	hex_to_block(bob_private_key, X448_KEY_OCTETS,
				 "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");

	// ---------------------------------------------------------------------------------------------------

	x448(alice_public_key, base_point, alice_private_key);
	status +=
		CHECK_BLOCK(alice_public_key, X448_KEY_OCTETS,
					"9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");

	// ---------------------------------------------------------------------------------------------------

	x448(bob_public_key, base_point, bob_private_key);
	status +=
		CHECK_BLOCK(bob_public_key, X448_KEY_OCTETS,
					"3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");

	// ---------------------------------------------------------------------------------------------------

	x448(alice_shared, bob_public_key, alice_private_key);
	status +=
		CHECK_BLOCK(alice_shared, X448_KEY_OCTETS,
					"07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

	// ---------------------------------------------------------------------------------------------------

	x448(bob_shared, alice_public_key, bob_private_key);
	status +=
		CHECK_BLOCK(bob_shared, X448_KEY_OCTETS,
					"07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

	// ---------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return x448_test_suite() + x448_ecdh();
}
