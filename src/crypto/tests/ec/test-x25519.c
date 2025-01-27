/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <x25519.h>
#include <test.h>

// Refer RFC 7748: Elliptic Curves for Security for test vectors

int32_t x25519_test_suite(void)
{
	int32_t status = 0;

	byte_t k[X25519_OCTET_SIZE] = {0};
	byte_t u[X25519_OCTET_SIZE] = {0};
	byte_t v[X25519_OCTET_SIZE] = {0};

	// ---------------------------------------------------------------------------------------------------

	memset(k, 0, X25519_OCTET_SIZE);
	memset(u, 0, X25519_OCTET_SIZE);
	memset(v, 0, X25519_OCTET_SIZE);

	hex_to_block(k, X25519_OCTET_SIZE, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
	hex_to_block(u, X25519_OCTET_SIZE, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

	x25519(v, u, k);

	status += CHECK_BLOCK(v, X25519_OCTET_SIZE, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

	// ---------------------------------------------------------------------------------------------------

	memset(k, 0, X25519_OCTET_SIZE);
	memset(u, 0, X25519_OCTET_SIZE);
	memset(v, 0, X25519_OCTET_SIZE);

	hex_to_block(k, X25519_OCTET_SIZE, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
	hex_to_block(u, X25519_OCTET_SIZE, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");

	x25519(v, u, k);

	status += CHECK_BLOCK(v, X25519_OCTET_SIZE, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

	// ---------------------------------------------------------------------------------------------------

	return status;
}

int32_t x25519_ecdh(void)
{
	int32_t status = 0;

	byte_t alice_private_key[X25519_OCTET_SIZE] = {0};
	byte_t alice_public_key[X25519_OCTET_SIZE] = {0};

	byte_t bob_private_key[X25519_OCTET_SIZE] = {0};
	byte_t bob_public_key[X25519_OCTET_SIZE] = {0};

	byte_t alice_shared[X25519_OCTET_SIZE] = {0};
	byte_t bob_shared[X25519_OCTET_SIZE] = {0};

	byte_t base_point[X25519_OCTET_SIZE] = {0};

	hex_to_block(base_point, X25519_OCTET_SIZE, "0900000000000000000000000000000000000000000000000000000000000000");
	hex_to_block(alice_private_key, X25519_OCTET_SIZE, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
	hex_to_block(bob_private_key, X25519_OCTET_SIZE, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

	// ---------------------------------------------------------------------------------------------------

	x25519(alice_public_key, base_point, alice_private_key);
	status += CHECK_BLOCK(alice_public_key, X25519_OCTET_SIZE, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

	// ---------------------------------------------------------------------------------------------------

	x25519(bob_public_key, base_point, bob_private_key);
	status += CHECK_BLOCK(bob_public_key, X25519_OCTET_SIZE, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

	// ---------------------------------------------------------------------------------------------------

	x25519(alice_shared, bob_public_key, alice_private_key);
	status += CHECK_BLOCK(alice_shared, X25519_OCTET_SIZE, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

	// ---------------------------------------------------------------------------------------------------

	x25519(bob_shared, alice_public_key, bob_private_key);
	status += CHECK_BLOCK(bob_shared, X25519_OCTET_SIZE, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

	// ---------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return x25519_test_suite() + x25519_ecdh();
}
