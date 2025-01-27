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

int32_t ec_nist_p256_test_suite(void)
{
	int32_t status = 0;
	char hex[128] = {0};

	ec_group *group = ec_group_new(EC_NIST_P256);
	bignum_t *k = bignum_new(group->bits);
	ec_point *r = NULL;

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

	k = bignum_set_hex(k, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254c", 64);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 128);
	bignum_get_hex(r->x, hex, 128);
	status += CHECK_HEX(hex, "0x51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed", 66);

	memset(hex, 0, 128);
	bignum_get_hex(r->y, hex, 128);
	status += CHECK_HEX(hex, "0x1f3e82566fb58d83751e40c9407586d9f2fed1002b27f7772e2f44bb025e925b", 66);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	ec_group_delete(group);
	bignum_delete(k);

	return status;
}

int32_t ec_nist_p521_test_suite(void)
{
	int32_t status = 0;
	char hex[256] = {0};

	ec_group *group = ec_group_new(EC_NIST_P521);
	bignum_t *k = bignum_new(group->bits);
	ec_point *r = NULL;

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 1);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 256);
	bignum_get_hex(r->x, hex, 256);
	status += CHECK_HEX(hex,
						"0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a42"
						"9bf97e7e31c2e5bd66",
						132);

	memset(hex, 0, 256);
	bignum_get_hex(r->y, hex, 256);
	status += CHECK_HEX(hex,
						"0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c"
						"24088be94769fd16650",
						133);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 2);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 256);
	bignum_get_hex(r->x, hex, 256);
	status += CHECK_HEX(hex,
						"0x433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd9"
						"67f43e3933ba6d783d",
						132);

	memset(hex, 0, 256);
	bignum_get_hex(r->y, hex, 256);
	status += CHECK_HEX(hex,
						"0xf4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c42dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4"
						"f71be356d661f41b02",
						132);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 3);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 256);
	bignum_get_hex(r->x, hex, 256);
	status += CHECK_HEX(hex,
						"0x1a73d352443de29195dd91d6a64b5959479b52a6e5b123d9ab9e5ad7a112d7a8dd1ad3f164a3a4832051da6bd16b59fe21baeb490862c32e"
						"a05a5919d2ede37ad7d",
						133);

	memset(hex, 0, 256);
	bignum_get_hex(r->y, hex, 256);
	status += CHECK_HEX(hex,
						"0x13e9b03b97dfa62ddd9979f86c6cab814f2f1557fa82a9d0317d2f8ab1fa355ceec2e2dd4cf8dc575b02d5aced1dec3c70cf105c9bc93a59"
						"0425f588ca1ee86c0e5",
						133);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 4);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 256);
	bignum_get_hex(r->x, hex, 256);
	status += CHECK_HEX(hex,
						"0x35b5df64ae2ac204c354b483487c9070cdc61c891c5ff39afc06c5d55541d3ceac8659e24afe3d0750e8b88e9f078af066a1d5025b08e5a5"
						"e2fbc87412871902f3",
						132);

	memset(hex, 0, 256);
	bignum_get_hex(r->y, hex, 256);
	status += CHECK_HEX(hex,
						"0x82096f84261279d2b673e0178eb0b4abb65521aef6e6e32e1b5ae63fe2f19907f279f283e54ba385405224f750a95b85eebb7faef04699d1"
						"d9e21f47fc346e4d0d",
						132);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 5);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 256);
	bignum_get_hex(r->x, hex, 256);
	status += CHECK_HEX(hex,
						"0x652bf3c52927a432c73dbc3391c04eb0bf7a596efdb53f0d24cf03dab8f177ace4383c0c6d5e3014237112feaf137e79a329d7e1e6d89317"
						"38d5ab5096ec8f3078",
						132);

	memset(hex, 0, 256);
	bignum_get_hex(r->y, hex, 256);
	status += CHECK_HEX(hex,
						"0x15be6ef1bdd6601d6ec8a2b73114a8112911cd8fe8e872e0051edd817c9a0347087bb6897c9072cf374311540211cf5ff79d1f007257354f"
						"7f8173cc3e8deb090cb",
						133);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	bignum_set_word(k, 8);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 256);
	bignum_get_hex(r->x, hex, 256);
	status += CHECK_HEX(hex,
						"0x822c40fb6301f7262a8348396b010e25bd4e29d8a9b003e0a8b8a3b05f826298f5bfea5b8579f49f08b598c1bc8d79e1ab56289b5a6f4040"
						"586f9ea54aa78ce68",
						131);

	memset(hex, 0, 256);
	bignum_get_hex(r->y, hex, 256);
	status += CHECK_HEX(hex,
						"0x16331911d5542fc482048fdab6e78853b9a44f8ede9e2c0715b5083de610677a8f189e9c0aa5911b4bff0ba0df065c578699f3ba94009471"
						"3538ad642f11f17801c",
						133);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	k = bignum_set_hex(k,
					   "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47ae"
					   "bb6fb71e91386402",
					   131);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 256);
	bignum_get_hex(r->x, hex, 256);
	status += CHECK_HEX(hex,
						"0x56d5d1d99d5b7f6346eeb65fda0b073a0c5f22e0e8f5483228f018d2c2f7114c5d8c308d0abfc698d8c9a6df30dce3bbc46f953f50fdc261"
						"9a01cead882816ecd4",
						132);

	memset(hex, 0, 256);
	bignum_get_hex(r->y, hex, 256);
	status += CHECK_HEX(hex,
						"0x1c2d2e48264555d5eef2e27ce85c6297b874a3a7d2fd7db0f228e242675d93421aa942f0d6c321361d46adc5cba6e31e5a061898ed5a2210"
						"384a3947436fadadae4",
						133);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	k = bignum_set_hex(k,
					   "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47ae"
					   "bb6fb71e91386407",
					   131);
	r = ec_point_multiply(group, NULL, group->g, k);

	memset(hex, 0, 256);
	bignum_get_hex(r->x, hex, 256);
	status += CHECK_HEX(hex,
						"0x433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd9"
						"67f43e3933ba6d783d",
						132);

	memset(hex, 0, 256);
	bignum_get_hex(r->y, hex, 256);
	status += CHECK_HEX(hex,
						"0x10b44733807924d98ff580c1311112c0f4a394aef83b25688bf54de5d66f93bd2444c1c882160dae0946c6c805665cdb70b1503416a123f0"
						"b08e41ca9299e0be4fd",
						133);

	ec_point_delete(r);

	// ---------------------------------------------------------------------------------------------------

	ec_group_delete(group);
	bignum_delete(k);

	return status;
}

int main()
{
	return ec_nist_p256_test_suite() + ec_nist_p521_test_suite();
}
