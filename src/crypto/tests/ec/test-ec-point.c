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

int32_t ec_nist_p384_test_suite(void)
{
	int32_t status = 0;

	ec_group *group = ec_group_new(EC_NIST_P384);
	bignum_t *x = NULL, *y = NULL;
	ec_point p;

	// ---------------------------------------------------------------------------------------------------

	x = bignum_set_hex(NULL, "732b0f83d303475584d88ed91cc74b367e9ffbfcc2d044d1485417d2731fa4f3b70347388e2308e9e43bdbf952465393", 96);
	y = bignum_set_hex(NULL, "d8d232a2c995a6ff133893dcfa9b559c11376eb999abf55edd51cc5edb7935500f80f55ca1a542a1b87f6c8c643b83d6", 96);

	p.x = x;
	p.y = y;

	if (ec_point_on_curve(group, &p) == 0)
	{
		++status;
	}

	bignum_delete(x);
	bignum_delete(y);

	// ---------------------------------------------------------------------------------------------------

	x = bignum_set_hex(NULL, "1f6e499ddca491b6e5da6e34eff16847284e816443cb9699f95e1449cc361327fb244f780cd704f55c1a4112fbda1264", 96);
	y = bignum_set_hex(NULL, "7b60b9f805598ca6a9521e5ccfd8e2c988fc450dc70f26202dd8567ef038f51e75441ae7b97b0debe3a2ed4b0442533a", 96);

	p.x = x;
	p.y = y;

	if (ec_point_on_curve(group, &p) == 0)
	{
		++status;
	}

	bignum_delete(x);
	bignum_delete(y);

	// ---------------------------------------------------------------------------------------------------

	x = bignum_set_hex(NULL, "a999b80932ea62b4689769225b3ff34b0709c4e32342a824799ca63dcce1f3ed8819e080fc7fa130c1881c8131f4bcb5", 96);
	y = bignum_set_hex(NULL, "b8c77d0868c2c159e1be6bcd60ec488ab31531c21e1cb8fe2493ed26ac848fde7d27823a9a4912650511a3d460e25ef2", 96);

	p.x = x;
	p.y = y;

	if (ec_point_on_curve(group, &p) != 0)
	{
		++status;
	}

	bignum_delete(x);
	bignum_delete(y);

	// ---------------------------------------------------------------------------------------------------

	x = bignum_set_hex(NULL, "25e5509a54f5fa62f94551dff3dfe210db1bb2bbc8fd4e672fbd5a211f9fd2f7eadc2b83fcd4198b7f857d9a2dc39c11", 96);
	y = bignum_set_hex(NULL, "98a4a13bc2f2d04bebd6d4e04412a9d306e57b90364583a6ec25bf6f0175bb5b397b8cfea83fd5d1e0ad052852b4aba7", 96);

	p.x = x;
	p.y = y;

	if (ec_point_on_curve(group, &p) != 0)
	{
		++status;
	}

	bignum_delete(x);
	bignum_delete(y);

	// ---------------------------------------------------------------------------------------------------

	ec_group_delete(group);

	return status;
}

int32_t ec_point_encode_test_suite(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	ec_group *group = ec_group_new(EC_NIST_P256);
	bignum_t *x = NULL, *y = NULL;
	ec_point p;

	byte_t buffer[256] = {0};

	// ---------------------------------------------------------------------------------------------------

	x = bignum_set_hex(NULL, "0x0", 3);
	y = bignum_set_hex(NULL, "0x0", 3);

	p.x = x;
	p.y = y;

	result = 0;
	memset(buffer, 0, 256);

	result = ec_point_encode(group, &p, buffer, 256, 0);
	status += CHECK_VALUE(result, 1);
	status += CHECK_BLOCK(buffer, 1, "00");

	result = 0;
	memset(buffer, 0, 256);

	result = ec_point_encode(group, &p, buffer, 256, 1);
	status += CHECK_VALUE(result, 1);
	status += CHECK_BLOCK(buffer, 1, "00");

	bignum_delete(x);
	bignum_delete(y);

	// ---------------------------------------------------------------------------------------------------

	x = bignum_set_hex(NULL, "741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c4", 64);
	y = bignum_set_hex(NULL, "f88f4b9463c7a024a98c7caab7784eab71146ed4ca45a358e66a00dd32bb7e2c", 64);

	p.x = x;
	p.y = y;

	result = 0;
	memset(buffer, 0, 256);

	result = ec_point_encode(group, &p, buffer, 256, 0);
	status += CHECK_VALUE(result, 65);
	status += CHECK_BLOCK(
		buffer, 65,
		"04741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c4f88f4b9463c7a024a98c7caab7784eab71146ed4ca45a358e66a00dd"
		"32bb7e2c");

	result = 0;
	memset(buffer, 0, 256);

	result = ec_point_encode(group, &p, buffer, 256, 1);
	status += CHECK_VALUE(result, 33);
	status += CHECK_BLOCK(buffer, 33, "02741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c4");

	bignum_delete(x);
	bignum_delete(y);

	// ---------------------------------------------------------------------------------------------------

	x = bignum_set_hex(NULL, "3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1", 64);
	y = bignum_set_hex(NULL, "6f66df64333b375edb37bc505b0b3975f6f2fb26a16776251d07110317d5c8bf", 64);

	p.x = x;
	p.y = y;

	result = 0;
	memset(buffer, 0, 256);

	result = ec_point_encode(group, &p, buffer, 256, 0);
	status += CHECK_VALUE(result, 65);
	status += CHECK_BLOCK(
		buffer, 65,
		"043ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d16f66df64333b375edb37bc505b0b3975f6f2fb26a16776251d071103"
		"17d5c8bf");

	result = 0;
	memset(buffer, 0, 256);

	result = ec_point_encode(group, &p, buffer, 256, 1);
	status += CHECK_VALUE(result, 33);
	status += CHECK_BLOCK(buffer, 33, "033ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1");

	bignum_delete(x);
	bignum_delete(y);

	// ---------------------------------------------------------------------------------------------------

	ec_group_delete(group);

	return status;
}

int32_t ec_point_decode_test_suite()
{
	int32_t status = 0;

	ec_group *group = ec_group_new(EC_NIST_P256);
	ec_point *p = NULL;

	byte_t buffer[256] = {0};
	char x[256] = {0}, y[256] = {0};

	// ---------------------------------------------------------------------------------------------------

	memset(buffer, 0, 256);
	memset(x, 0, 256);
	memset(y, 0, 256);

	hex_to_block(buffer, 1, "00");

	p = ec_point_decode(group, NULL, buffer, 1);

	bignum_get_hex(p->x, x, 256);
	bignum_get_hex(p->y, y, 256);

	status += CHECK_HEX(x, "0x0", 3);
	status += CHECK_HEX(y, "0x0", 3);

	ec_point_delete(p);

	// ---------------------------------------------------------------------------------------------------

	memset(buffer, 0, 256);
	memset(x, 0, 256);
	memset(y, 0, 256);

	hex_to_block(
		buffer, 65,
		"04741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c4f88f4b9463c7a024a98c7caab7784eab71146ed4ca45a358e66a00dd"
		"32bb7e2c");

	p = ec_point_decode(group, NULL, buffer, 65);

	bignum_get_hex(p->x, x, 256);
	bignum_get_hex(p->y, y, 256);

	status += CHECK_HEX(x + 2, "741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c4", 64);
	status += CHECK_HEX(y + 2, "f88f4b9463c7a024a98c7caab7784eab71146ed4ca45a358e66a00dd32bb7e2c", 64);

	ec_point_delete(p);

	// ---------------------------------------------------------------------------------------------------

	memset(buffer, 0, 256);
	memset(x, 0, 256);
	memset(y, 0, 256);

	hex_to_block(buffer, 33, "02741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c4");

	p = ec_point_decode(group, NULL, buffer, 33);

	bignum_get_hex(p->x, x, 256);
	bignum_get_hex(p->y, y, 256);

	status += CHECK_HEX(x + 2, "741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c4", 64);
	status += CHECK_HEX(y + 2, "f88f4b9463c7a024a98c7caab7784eab71146ed4ca45a358e66a00dd32bb7e2c", 64);

	ec_point_delete(p);

	// ---------------------------------------------------------------------------------------------------

	memset(buffer, 0, 256);
	memset(x, 0, 256);
	memset(y, 0, 256);

	hex_to_block(
		buffer, 65,
		"043ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d16f66df64333b375edb37bc505b0b3975f6f2fb26a16776251d071103"
		"17d5c8bf");

	p = ec_point_decode(group, NULL, buffer, 65);

	bignum_get_hex(p->x, x, 256);
	bignum_get_hex(p->y, y, 256);

	status += CHECK_HEX(x + 2, "3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1", 64);
	status += CHECK_HEX(y + 2, "6f66df64333b375edb37bc505b0b3975f6f2fb26a16776251d07110317d5c8bf", 64);

	ec_point_delete(p);

	// ---------------------------------------------------------------------------------------------------

	memset(buffer, 0, 256);
	memset(x, 0, 256);
	memset(y, 0, 256);

	hex_to_block(buffer, 33, "033ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1");

	p = ec_point_decode(group, NULL, buffer, 33);

	bignum_get_hex(p->x, x, 256);
	bignum_get_hex(p->y, y, 256);

	status += CHECK_HEX(x + 2, "3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1", 64);
	status += CHECK_HEX(y + 2, "6f66df64333b375edb37bc505b0b3975f6f2fb26a16776251d07110317d5c8bf", 64);

	ec_point_delete(p);

	// ---------------------------------------------------------------------------------------------------

	ec_group_delete(group);
	group = ec_group_new(EC_NIST_P224);

	// ---------------------------------------------------------------------------------------------------

	memset(buffer, 0, 256);
	memset(x, 0, 256);
	memset(y, 0, 256);

	hex_to_block(buffer, 29, "02aea9e17a306517eb89152aa7096d2c381ec813c51aa880e7bee2c0fd");

	p = ec_point_decode(group, NULL, buffer, 29);

	bignum_get_hex(p->x, x, 256);
	bignum_get_hex(p->y, y, 256);

	status += CHECK_HEX(x + 2, "aea9e17a306517eb89152aa7096d2c381ec813c51aa880e7bee2c0fd", 56);
	status += CHECK_HEX(y + 2, "c644cf154cc81f5ade49345e541b4d4b5c1adb3eb5c01c14ee949aa2", 56);

	ec_point_delete(p);

	// ---------------------------------------------------------------------------------------------------

	memset(buffer, 0, 256);
	memset(x, 0, 256);
	memset(y, 0, 256);

	hex_to_block(buffer, 29, "03858e6f9cc6c12c31f5df124aa77767b05c8bc021bd683d2b55571550");

	p = ec_point_decode(group, NULL, buffer, 29);

	bignum_get_hex(p->x, x, 256);
	bignum_get_hex(p->y, y, 256);

	status += CHECK_HEX(x + 2, "858e6f9cc6c12c31f5df124aa77767b05c8bc021bd683d2b55571550", 56);
	status += CHECK_HEX(y + 2, "fb9232c15a3bc7673a3a03b0253824c53d0fd1411b1cabe2e187fb87", 56);

	ec_point_delete(p);

	// ---------------------------------------------------------------------------------------------------

	ec_group_delete(group);

	return status;
}

int main()
{
	return ec_nist_p384_test_suite() + ec_point_encode_test_suite() + ec_point_decode_test_suite();
}
