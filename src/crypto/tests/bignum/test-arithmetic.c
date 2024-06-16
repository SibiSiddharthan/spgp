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

int32_t bignum_add_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *b = NULL, *c = NULL;
	char hex[64] = {0};

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "200000fd00000000fd000000fd000000", 32);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0x300001fa00000001fa000001fa000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "b00000fd00000000fd000000fd000000", 32);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0x1500001fa00000001fa000001fa000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "fd000000fd000000", 16);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0xa00000fd00000001fa000001fa000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-a00000fd00000000fd000000fd000000", 33);
	b = bignum_set_hex(NULL, "-b00000fd00000000fd000000fd000000", 33);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0x1500001fa00000001fa000001fa000000", 36);
	status += CHECK_VALUE(result, 36);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "200000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000000", 33);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0x10000000000000000000000000000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-200000fd00000000fd000000fd000000", 33);
	b = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0x10000000000000000000000000000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000000", 33);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000001", 33);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0x1", 4);
	status += CHECK_VALUE(result, 4);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	return status;
}

int32_t bignum_sub_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *b = NULL, *c = NULL;
	char hex[64] = {0};

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "200000fd00000000fd000000fd000000", 32);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0x10000000000000000000000000000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "100000fd00000000fd000000fd000004", 32);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0x4", 4);
	status += CHECK_VALUE(result, 4);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000000", 33);
	b = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000004", 33);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0x4", 3);
	status += CHECK_VALUE(result, 3);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "fd000000fd000000", 16);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0xa00000fd000000000000000000000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "fd000000fd000000", 16);
	c = bignum_sub(NULL, b, a);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0xa00000fd000000000000000000000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-a00000fd00000000fd000000fd000000", 33);
	b = bignum_set_hex(NULL, "-fd000000fd000000", 17);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0xa00000fd000000000000000000000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "-fd000000fd000000", 17);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0xa00000fd00000001fa000001fa000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_free(a);
	bignum_free(b);
	bignum_free(c);

	// ------------------------------------------------------------------------

	return status;
}

int main()
{
	return bignum_cmp_tests() + bignum_add_tests() + bignum_sub_tests();
}
