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

int main()
{
	return ec_nist_p384_test_suite();
}
