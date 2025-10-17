/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <ec.h>
#include <test.h>

int32_t ec_nist_keygen_test_suite(void)
{
	int32_t status = 0;
	char hex[128] = {0};

	ec_group *group = NULL;
	ec_key *key = NULL;
	bignum_t *d = NULL;

	// ---------------------------------------------------------------------------------------------------

	group = ec_group_new(EC_NIST_P384);
	d = bignum_set_hex(NULL, "5394f7973ea868c52bf3ff8d8ceeb4db90a683653b12485d5f627c3ce5abd8978fc9673d14a71d925747931662493c37", 96);

	key = ec_key_generate(group, d);

	memset(hex, 0, 128);
	bignum_get_hex(key->q->x, hex, 128);
	status += CHECK_HEX(hex, "0xfd3c84e5689bed270e601b3d80f90d67a9ae451cce890f53e583229ad0e2ee645611fa9936dfa45306ec18066774aa24", 98);

	memset(hex, 0, 128);
	bignum_get_hex(key->q->y, hex, 128);
	status += CHECK_HEX(hex, "0xb83ca4126cfc4c4d1d18a4b6c21c7f699d5123dd9c24f66f833846eeb58296196b42ec06425db5b70a4b81b7fcf705a0", 98);

	ec_key_delete(key);

	// ---------------------------------------------------------------------------------------------------

	group = ec_group_new(EC_NIST_P384);
	d = bignum_set_hex(NULL, "3a7b2a6a03c92154f4ef31dd257bd9d3397494da4c93dc033a1c7925a295ce12412797ac995191b665229ad6db881e6e", 96);

	key = ec_key_generate(group, d);

	memset(hex, 0, 128);
	bignum_get_hex(key->q->x, hex, 128);
	status += CHECK_HEX(hex, "0x9e248419857ca4a03c1f2ba99eddad34ce1904ba486c73e3903adb7fc5e63a6d397a9a1a5e06f1d62d78cb7038a518d3", 98);

	memset(hex, 0, 128);
	bignum_get_hex(key->q->y, hex, 128);
	status += CHECK_HEX(hex, "0x86a15f544ecd494b6c8cd5f561832a2d73fb83d0a8a76f10808022b47f2fff1e8730c43684ad17b6bd049c586b4d3cdf", 98);

	ec_key_delete(key);

	// ---------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return ec_nist_keygen_test_suite();
}
