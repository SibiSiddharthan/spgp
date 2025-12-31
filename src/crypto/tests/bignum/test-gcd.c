/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <string.h>
#include <bignum.h>

#include <test.h>

int32_t bignum_euclid_gcd_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *b = NULL, *r = NULL;
	char hex[512] = {0};

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "0", 1);
	b = bignum_set_hex(NULL, "0", 1);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "1", 1);
	b = bignum_set_hex(NULL, "0", 1);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "1", 1);
	b = bignum_set_hex(NULL, "1", 1);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "0", 1);
	b = bignum_set_hex(NULL, "70030ffeeea3deaea19387f4f1d0f460a6954a2a9cb98290602ac09036143ef8eb9692f3eac22961811083e073ee0be1506c24d7b0d4",
					   108);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex, "0x70030ffeeea3deaea19387f4f1d0f460a6954a2a9cb98290602ac09036143ef8eb9692f3eac22961811083e073ee0be1506c24d7b0d4", 110);
	status += CHECK_VALUE(result, 110);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "0", 1);
	b = bignum_set_hex(
		NULL, "-70030ffeeea3deaea19387f4f1d0f460a6954a2a9cb98290602ac09036143ef8eb9692f3eac22961811083e073ee0be1506c24d7b0d4", 109);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex, "0x70030ffeeea3deaea19387f4f1d0f460a6954a2a9cb98290602ac09036143ef8eb9692f3eac22961811083e073ee0be1506c24d7b0d4", 110);
	status += CHECK_VALUE(result, 110);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "f", 1);
	b = bignum_set_hex(NULL, "3", 1);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x3", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "ffffffffffffff", 14);
	b = bignum_set_hex(NULL, "fffffff", 7);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0xfffffff", 9);
	status += CHECK_VALUE(result, 9);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		251);
	b = bignum_set_hex(
		NULL,
		"1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		126);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex,
		"0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		128);
	status += CHECK_VALUE(result, 128);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-4f4db668e2b044ee972eec62b06264", 31);
	b = bignum_set_hex(NULL, "-be55936205e72ebb3e0543b8d83628", 31);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0xc", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a8de6c3578a1f2fb69adfdb7cd687eb4", 32);
	b = bignum_set_hex(NULL, "-1371dea9653f87dafa5512b89b2691b4c", 34);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x4", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "1375f0dac727bcd1fe8d4b1d1dd563f236dcc58e1a36fbdfd", 49);
	b = bignum_set_hex(NULL, "a96ba42e882a321930399b7788e0fec9a8f76f44b5432a00", 48);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL,
					   "1079904a6aa766e7147e5ea77b46d82825d452e657b39aef739ee1f3d4c3276cedb11e551f4e82f7a6f9e57b72a61e82ab37a15967435a63499"
					   "336a0c7751db2ebfb83d4244fa1165175c8535b9900ab015c645b674f7347c99ba63a9a163657c37cd62cb49cd3ec9213e59ce4fff1834716e",
					   229);
	b = bignum_set_hex(NULL,
					   "199d3d0b3b117127fa5ba38d7f82b35db7298f75c449ea8b2de1064e22d1ebf42cfe550c16b0e5a706826811b60d71e1dd05519aae7ac82fdb9"
					   "3f5618b6c0c0287d6089cdb8ef6dcb48e0f55495764163d488140f508f44240c9e2d591201359c316fef38fda4e8b231cc35e3b94b38d4b0a1",
					   229);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"6caccf36a233543e132092e2ea688fa1d46510f190d4f6c9410e2d2a0299f63aa28609c57093f43cf67bf816cc87f8fac3d7f14cfad70b815a42f9980035b38b18"
		"d93576595dffcf7f7732303662d091bbaffd3fb56b97204b265e06455e28c040d7b47b22b71b2d489af5ed892f1cc968f6f8567c5dc2eeca6cd3f79369f24b",
		256);
	b = bignum_set_hex(
		NULL,
		"38f7ec4ff7e5a9557bd0b88d436e684f6ecb99550b0efa916a6ecfe1320e5adac4d7c4efb57d05163b22584c705b5b143c4cf3e253f1f3a05ed2c1505abe8fed98"
		"2e8e19aee09c93160109d7008ed6dc9d41b243736a0aca8913ced6cec18cefc9674d0edcfe2dcfdc81eeb2820ae8d4aa813ee7c2183c5539f58796774f2fc5",
		256);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x3", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"-8e2c670baf6c5404785ee3e5a5609c1b75b94bac7948dc0306e52401502549ee563483d732acb356e6fc597df29ff45eb4efb114f3826098f1c405a0e8264771d"
		"c"
		"e5cf63a49db23931b11474bb78cbd4592c7bba846a210260193064363eef5f9c7ea34b9167ba6aba693cbf24b1108accb8e1c0fbe717fbfe1d8cb4e9c09060",
		257);
	b = bignum_set_hex(
		NULL,
		"8eadfec28a09c920b35acb8a2f1b7ab25812431878860737c18c96afe11ed5ac55465cbdbed96fdf333f07e0568b7c77aa0de151d31b347314ffda288188a71b7f"
		"875716a8989894974f415e37490c591df521d1421cd1e3f32820f23c5eef7d78223066e5d4ef1c8a0ab1900eaa3298c4f194586db0c3153810f5bf81df3cc0",
		256);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x20", 4);
	status += CHECK_VALUE(result, 4);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL,
					   "c87607c87d106cd834f47c0b318b2cc26a097d867e8a2d99a0b57dffbac2a81d9e024ab10975831a2442357dc6cf51db46d0875d26c47776a4b"
					   "7514e04834d2a7415ab493469617ddb3a3daa42f6b63a0d3945fc88d966e590b969d0d0166003f0f5b87120b82a9fdc2eccbea167263658",
					   226);
	b = bignum_set_hex(NULL,
					   "e0ec85385e3444b998d097b598f14a3a8bb91507df297629c9edc8cc652baae04e4d2ed2871eb0350d5601f5f005e184b3123d97390347e5ced"
					   "a80c50bf866dc7f5b467646b443fb569be05b982614c630a6b5ddf869067bb6b00b7c2685a3c1404a35fc5d1adf9922b0a77ec487f6f37d4d",
					   228);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex, "0x1ac13ed8468055875db58597a872f1923d65aedb6d06b7d779dbc5890815070172a39b7221e701354db329a1d6d229fab23300227bcb6bc7299", 117);
	status += CHECK_VALUE(result, 117);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"aca40d6e53c58740ecc2d8e3faca8590390ae0fbfc634c065ddb53062164cd646ac2aa4dcf6107d9a6c74bbc013d8da5cd99ba62e5e90e6ed44dc1a1ade96d402d"
		"297a265a4861c2d32d2edee48c02e20a38eef1a7eb698661a03d5f1f11d0c56ff71a34110e5a0003fa83329cc860eb74347e86084f806ee5",
		242);
	b = bignum_set_hex(
		NULL,
		"213fd4fd30cb71b48b070590f5e32e479dc5cd3c4647a582e7a259e59fc50ff12d086a637720ed9f77ea7496e233932d2ba95d8375d09d0a559bef64cdaa3e5c3d"
		"635d8e32456a9c0d3d9182a2a899de5916a747c5c2493bbae171775d8850df88341872547766f8488acceccc49d88988e2aae3a7942fb005",
		242);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex, "0x149f0d624a09ed71cfa35f28d42e0d74ffda6b91a522ca050e3b51b85c57282b3c181ec6a3a792b187c284e99961ca8c1fda63b1d44b48c6d1857a5275",
		124);
	status += CHECK_VALUE(result, 124);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL,
					   "da140841b03751177eb5ca4430bb409cadfb316a40adffaed826d6cf4d5ef92757a727eeab5754e6f2ef8cc029cd1c339321e38f5da03e80969"
					   "65cad6616350c6770ff708000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
					   "0000000000000000000000000000000000000000000",
					   273);
	b = bignum_set_hex(NULL,
					   "1f6302078f3414043c023607c4a7294c751554cea7ecd6104062f4ca153608d8c36c2db671b35c6b5cd6b49293ee5ef40edc30208d1358c228c"
					   "7731f91ae2076e7bbac1f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
					   "0000000000000000000000000000000000000000000",
					   273);
	r = bignum_euclid_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex,
						"0x1400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
						"00000000000000000000000000",
						140);
	status += CHECK_VALUE(result, 140);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	return status;
}

int32_t bignum_binary_gcd_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *b = NULL, *r = NULL;
	char hex[512] = {0};

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "0", 1);
	b = bignum_set_hex(NULL, "0", 1);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "1", 1);
	b = bignum_set_hex(NULL, "0", 1);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "1", 1);
	b = bignum_set_hex(NULL, "1", 1);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "0", 1);
	b = bignum_set_hex(NULL, "70030ffeeea3deaea19387f4f1d0f460a6954a2a9cb98290602ac09036143ef8eb9692f3eac22961811083e073ee0be1506c24d7b0d4",
					   108);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex, "0x70030ffeeea3deaea19387f4f1d0f460a6954a2a9cb98290602ac09036143ef8eb9692f3eac22961811083e073ee0be1506c24d7b0d4", 110);
	status += CHECK_VALUE(result, 110);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "0", 1);
	b = bignum_set_hex(
		NULL, "-70030ffeeea3deaea19387f4f1d0f460a6954a2a9cb98290602ac09036143ef8eb9692f3eac22961811083e073ee0be1506c24d7b0d4", 109);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex, "0x70030ffeeea3deaea19387f4f1d0f460a6954a2a9cb98290602ac09036143ef8eb9692f3eac22961811083e073ee0be1506c24d7b0d4", 110);
	status += CHECK_VALUE(result, 110);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "f", 1);
	b = bignum_set_hex(NULL, "3", 1);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x3", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "ffffffffffffff", 14);
	b = bignum_set_hex(NULL, "fffffff", 7);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0xfffffff", 9);
	status += CHECK_VALUE(result, 9);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		251);
	b = bignum_set_hex(
		NULL,
		"1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		126);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex,
		"0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		128);
	status += CHECK_VALUE(result, 128);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-4f4db668e2b044ee972eec62b06264", 31);
	b = bignum_set_hex(NULL, "-be55936205e72ebb3e0543b8d83628", 31);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0xc", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a8de6c3578a1f2fb69adfdb7cd687eb4", 32);
	b = bignum_set_hex(NULL, "-1371dea9653f87dafa5512b89b2691b4c", 34);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x4", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "1375f0dac727bcd1fe8d4b1d1dd563f236dcc58e1a36fbdfd", 49);
	b = bignum_set_hex(NULL, "a96ba42e882a321930399b7788e0fec9a8f76f44b5432a00", 48);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL,
					   "1079904a6aa766e7147e5ea77b46d82825d452e657b39aef739ee1f3d4c3276cedb11e551f4e82f7a6f9e57b72a61e82ab37a15967435a63499"
					   "336a0c7751db2ebfb83d4244fa1165175c8535b9900ab015c645b674f7347c99ba63a9a163657c37cd62cb49cd3ec9213e59ce4fff1834716e",
					   229);
	b = bignum_set_hex(NULL,
					   "199d3d0b3b117127fa5ba38d7f82b35db7298f75c449ea8b2de1064e22d1ebf42cfe550c16b0e5a706826811b60d71e1dd05519aae7ac82fdb9"
					   "3f5618b6c0c0287d6089cdb8ef6dcb48e0f55495764163d488140f508f44240c9e2d591201359c316fef38fda4e8b231cc35e3b94b38d4b0a1",
					   229);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"6caccf36a233543e132092e2ea688fa1d46510f190d4f6c9410e2d2a0299f63aa28609c57093f43cf67bf816cc87f8fac3d7f14cfad70b815a42f9980035b38b18"
		"d93576595dffcf7f7732303662d091bbaffd3fb56b97204b265e06455e28c040d7b47b22b71b2d489af5ed892f1cc968f6f8567c5dc2eeca6cd3f79369f24b",
		256);
	b = bignum_set_hex(
		NULL,
		"38f7ec4ff7e5a9557bd0b88d436e684f6ecb99550b0efa916a6ecfe1320e5adac4d7c4efb57d05163b22584c705b5b143c4cf3e253f1f3a05ed2c1505abe8fed98"
		"2e8e19aee09c93160109d7008ed6dc9d41b243736a0aca8913ced6cec18cefc9674d0edcfe2dcfdc81eeb2820ae8d4aa813ee7c2183c5539f58796774f2fc5",
		256);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x3", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"-8e2c670baf6c5404785ee3e5a5609c1b75b94bac7948dc0306e52401502549ee563483d732acb356e6fc597df29ff45eb4efb114f3826098f1c405a0e8264771d"
		"c"
		"e5cf63a49db23931b11474bb78cbd4592c7bba846a210260193064363eef5f9c7ea34b9167ba6aba693cbf24b1108accb8e1c0fbe717fbfe1d8cb4e9c09060",
		257);
	b = bignum_set_hex(
		NULL,
		"8eadfec28a09c920b35acb8a2f1b7ab25812431878860737c18c96afe11ed5ac55465cbdbed96fdf333f07e0568b7c77aa0de151d31b347314ffda288188a71b7f"
		"875716a8989894974f415e37490c591df521d1421cd1e3f32820f23c5eef7d78223066e5d4ef1c8a0ab1900eaa3298c4f194586db0c3153810f5bf81df3cc0",
		256);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x20", 4);
	status += CHECK_VALUE(result, 4);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL,
					   "c87607c87d106cd834f47c0b318b2cc26a097d867e8a2d99a0b57dffbac2a81d9e024ab10975831a2442357dc6cf51db46d0875d26c47776a4b"
					   "7514e04834d2a7415ab493469617ddb3a3daa42f6b63a0d3945fc88d966e590b969d0d0166003f0f5b87120b82a9fdc2eccbea167263658",
					   226);
	b = bignum_set_hex(NULL,
					   "e0ec85385e3444b998d097b598f14a3a8bb91507df297629c9edc8cc652baae04e4d2ed2871eb0350d5601f5f005e184b3123d97390347e5ced"
					   "a80c50bf866dc7f5b467646b443fb569be05b982614c630a6b5ddf869067bb6b00b7c2685a3c1404a35fc5d1adf9922b0a77ec487f6f37d4d",
					   228);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex, "0x1ac13ed8468055875db58597a872f1923d65aedb6d06b7d779dbc5890815070172a39b7221e701354db329a1d6d229fab23300227bcb6bc7299", 117);
	status += CHECK_VALUE(result, 117);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"aca40d6e53c58740ecc2d8e3faca8590390ae0fbfc634c065ddb53062164cd646ac2aa4dcf6107d9a6c74bbc013d8da5cd99ba62e5e90e6ed44dc1a1ade96d402d"
		"297a265a4861c2d32d2edee48c02e20a38eef1a7eb698661a03d5f1f11d0c56ff71a34110e5a0003fa83329cc860eb74347e86084f806ee5",
		242);
	b = bignum_set_hex(
		NULL,
		"213fd4fd30cb71b48b070590f5e32e479dc5cd3c4647a582e7a259e59fc50ff12d086a637720ed9f77ea7496e233932d2ba95d8375d09d0a559bef64cdaa3e5c3d"
		"635d8e32456a9c0d3d9182a2a899de5916a747c5c2493bbae171775d8850df88341872547766f8488acceccc49d88988e2aae3a7942fb005",
		242);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex, "0x149f0d624a09ed71cfa35f28d42e0d74ffda6b91a522ca050e3b51b85c57282b3c181ec6a3a792b187c284e99961ca8c1fda63b1d44b48c6d1857a5275",
		124);
	status += CHECK_VALUE(result, 124);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	a = bignum_set_hex(NULL,
					   "da140841b03751177eb5ca4430bb409cadfb316a40adffaed826d6cf4d5ef92757a727eeab5754e6f2ef8cc029cd1c339321e38f5da03e80969"
					   "65cad6616350c6770ff708000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
					   "0000000000000000000000000000000000000000000",
					   273);
	b = bignum_set_hex(NULL,
					   "1f6302078f3414043c023607c4a7294c751554cea7ecd6104062f4ca153608d8c36c2db671b35c6b5cd6b49293ee5ef40edc30208d1358c228c"
					   "7731f91ae2076e7bbac1f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
					   "0000000000000000000000000000000000000000000",
					   273);
	r = bignum_binary_gcd(NULL, NULL, a, b);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex,
						"0x1400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
						"00000000000000000000000000",
						140);
	status += CHECK_VALUE(result, 140);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(r);

	// --------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return bignum_euclid_gcd_tests() + bignum_binary_gcd_tests();
}
