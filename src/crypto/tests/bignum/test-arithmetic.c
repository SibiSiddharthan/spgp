/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <string.h>
#include <bignum.h>

#include <test.h>

int32_t bignum_cmp_tests(void)
{
	int32_t status = 0;
	int32_t result = 0;
	bignum_t *a = NULL, *b = NULL;

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "200000fd00000000fd000000fd000000", 32);

	result = bignum_cmp(a, b);
	status += CHECK_VALUE(result, -1);

	result = bignum_cmp(b, a);
	status += CHECK_VALUE(result, 1);

	result = bignum_cmp(a, a);
	status += CHECK_VALUE(result, 0);

	bignum_free(a);
	bignum_free(b);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "-200000fd00000000fd000000fd000000", 33);

	result = bignum_cmp(a, b);
	status += CHECK_VALUE(result, 1);

	result = bignum_cmp(b, a);
	status += CHECK_VALUE(result, -1);

	result = bignum_cmp(b, b);
	status += CHECK_VALUE(result, 0);

	result = bignum_cmp_abs(b, a);
	status += CHECK_VALUE(result, 1);

	bignum_free(a);
	bignum_free(b);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000000", 33);
	b = bignum_set_hex(NULL, "-200000fd00000000fd000000fd000000", 33);

	result = bignum_cmp(a, b);
	status += CHECK_VALUE(result, 1);

	result = bignum_cmp(b, a);
	status += CHECK_VALUE(result, -1);

	result = bignum_cmp_abs(a, b);
	status += CHECK_VALUE(result, -1);

	result = bignum_cmp_abs(b, a);
	status += CHECK_VALUE(result, 1);

	bignum_free(a);
	bignum_free(b);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000002", 32);
	b = bignum_set_hex(NULL, "100000fd00000000fd000000fd000001", 32);

	result = bignum_cmp(a, b);
	status += CHECK_VALUE(result, 1);

	result = bignum_cmp(b, a);
	status += CHECK_VALUE(result, -1);

	bignum_free(a);
	bignum_free(b);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "0x00000000000000000", 19);
	b = bignum_set_hex(NULL, "-0x00000000000", 14);

	result = bignum_cmp(a, b);
	status += CHECK_VALUE(result, 0);

	result = bignum_cmp(b, a);
	status += CHECK_VALUE(result, 0);

	bignum_free(a);
	bignum_free(b);

	// ------------------------------------------------------------------------

	return status;
}

int main()
{
	return bignum_cmp_tests();
}
