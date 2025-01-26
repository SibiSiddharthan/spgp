/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ec.h>
#include <test.h>

int32_t ec_nist_test_suite(void)
{
	int32_t status = 0;
	char hex[128] = {0};

	ec_group *group = ec_group_new(EC_NIST_P256);
	bignum_t *k = NULL;
	ec_point *r = NULL;

	k = bignum_new(256);

	memset(hex, 0, 128);
	bignum_get_hex(group->p, hex, 128);
	status += CHECK_HEX(hex, "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 66);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 1);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 66);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 2);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0x7775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1", 65);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 3);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0x8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032", 66);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 4);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0xe2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0xe0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6", 66);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 5);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0x51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0xe0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4", 66);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 8);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0x62d9779dbee9b0534042742d3ab54cadc1d238980fce97dbb4dd9dc1db6fb393", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0xad5accbd91e9d8244ff15d771167cee0a2ed51f6bbe76a78da540a6a0f09957e", 66);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 16);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0x76a94d138a6b41858b821c629836315fcd28392eff6ca038a5eb4787e1277c6e", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0xa985fe61341f260e6cb0a1b5e11e87208599a0040fc78baa0e9ddd724b8c5110", 66);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 18);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0x1057e0ab5780f470defc9378d1c7c87437bb4c6f9ea55c63d936266dbd781fda", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0xf6f1645a15cbe5dc9fa9b7dfd96ee5a7dcc11b5c5ef4f1f78d83b3393c6a45a2", 66);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	k = bignum_set_hex(k, "41ffc1fffffe01fffc0003fffe0007c001fff00003fff07ffe0007c000000003", 64);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0x9eace8f4b071e677c5350b02f2bb2b384aae89d58aa72ca97a170572e0fb222f", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0x1bbdaec2430b09b93f7cb08678636ce12eaafd58390699b5fd2f6e1188fc2a78", 66);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return ec_nist_test_suite();
}
