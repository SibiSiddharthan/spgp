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

	bignum_delete(a);
	bignum_delete(b);

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

	bignum_delete(a);
	bignum_delete(b);

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

	bignum_delete(a);
	bignum_delete(b);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000002", 32);
	b = bignum_set_hex(NULL, "100000fd00000000fd000000fd000001", 32);

	result = bignum_cmp(a, b);
	status += CHECK_VALUE(result, 1);

	result = bignum_cmp(b, a);
	status += CHECK_VALUE(result, -1);

	bignum_delete(a);
	bignum_delete(b);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "0x00000000000000000", 19);
	b = bignum_set_hex(NULL, "-0x00000000000", 14);

	result = bignum_cmp(a, b);
	status += CHECK_VALUE(result, 0);

	result = bignum_cmp(b, a);
	status += CHECK_VALUE(result, 0);

	bignum_delete(a);
	bignum_delete(b);

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

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "b00000fd00000000fd000000fd000000", 32);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0x1500001fa00000001fa000001fa000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "fd000000fd000000", 16);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0xa00000fd00000001fa000001fa000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-a00000fd00000000fd000000fd000000", 33);
	b = bignum_set_hex(NULL, "-b00000fd00000000fd000000fd000000", 33);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0x1500001fa00000001fa000001fa000000", 36);
	status += CHECK_VALUE(result, 36);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "200000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000000", 33);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0x10000000000000000000000000000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-200000fd00000000fd000000fd000000", 33);
	b = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0x10000000000000000000000000000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000000", 33);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000001", 33);
	c = bignum_add(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0x1", 4);
	status += CHECK_VALUE(result, 4);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

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

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "100000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "100000fd00000000fd000000fd000004", 32);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0x4", 4);
	status += CHECK_VALUE(result, 4);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000000", 33);
	b = bignum_set_hex(NULL, "-100000fd00000000fd000000fd000004", 33);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0x4", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "fd000000fd000000", 16);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0xa00000fd000000000000000000000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "fd000000fd000000", 16);
	c = bignum_sub(NULL, b, a);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0xa00000fd000000000000000000000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "-a00000fd00000000fd000000fd000000", 33);
	b = bignum_set_hex(NULL, "-fd000000fd000000", 17);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "-0xa00000fd000000000000000000000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "a00000fd00000000fd000000fd000000", 32);
	b = bignum_set_hex(NULL, "-fd000000fd000000", 17);
	c = bignum_sub(NULL, a, b);

	memset(hex, 0, 64);
	result = bignum_get_hex(c, hex, 64);

	status += CHECK_HEX(hex, "0xa00000fd00000001fa000001fa000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	return status;
}

int32_t bignum_mul_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *b = NULL, *c = NULL;
	char hex[128] = {0};

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "10000001000000000100000001000000", 32);
	b = bignum_set_hex(NULL, "f000000f000000000f0000000f000000", 32);
	c = bignum_mul(NULL, a, b);

	memset(hex, 0, 128);
	result = bignum_get_hex(c, hex, 128);

	status += CHECK_HEX(hex, "0xf000001e000000f01e000001fe000001e0f0000001e0000000f000000000000", 65);
	status += CHECK_VALUE(result, 65);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "cd0000000cd00000000cd000000cd000000", 35);
	b = bignum_set_hex(NULL, "-ab00000000ab000000ab000000", 27);
	c = bignum_mul(NULL, a, b);

	memset(hex, 0, 128);
	result = bignum_get_hex(c, hex, 128);

	status += CHECK_HEX(hex, "-0x88ef00000917df00009a0ce00011266ef000111de000088ef000000000000", 64);
	status += CHECK_VALUE(result, 64);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(c);

	// ------------------------------------------------------------------------

	return status;
}

int32_t bignum_div_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_ctx *bctx = NULL;
	bignum_t *dd = NULL, *dv = NULL, *q = NULL, *r = NULL;
	char qhex[128] = {0};
	char rhex[128] = {0};

	bctx = bignum_ctx_new(1024);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "0", 1);
	dv = bignum_set_hex(NULL, "10000001000000000100000001000000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "10000001000000000100000001000000", 32);
	dv = bignum_set_hex(NULL, "10000001000000000100000001000000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "10000001000000000100000001000001", 32);
	dv = bignum_set_hex(NULL, "10000001000000000100000001000000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "-10000001000000000100000001000000", 33);
	dv = bignum_set_hex(NULL, "10000001000000000100000001000000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "-0x1", 4);
	status += CHECK_VALUE(result, 4);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "-10000001000000000100000001000001", 33);
	dv = bignum_set_hex(NULL, "10000001000000000100000001000000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "-0x2", 4);
	status += CHECK_VALUE(result, 4);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0x10000001000000000100000000ffffff", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "10000001000000000100000001000001", 32);
	dv = bignum_set_hex(NULL, "-10000001000000000100000001000000", 33);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "-0x2", 4);
	status += CHECK_VALUE(result, 4);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "-0x10000001000000000100000000ffffff", 35);
	status += CHECK_VALUE(result, 35);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "10000001000000000100000001000001", 32);
	dv = bignum_set_hex(NULL, "-10000001000000000100000001000000", 33);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "-0x2", 4);
	status += CHECK_VALUE(result, 4);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "-0x10000001000000000100000000ffffff", 35);
	status += CHECK_VALUE(result, 35);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "-10000001000000000100000001000001", 33);
	dv = bignum_set_hex(NULL, "-10000001000000000100000001000000", 33);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "0x1", 3);
	status += CHECK_VALUE(result, 3);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "-0x1", 4);
	status += CHECK_VALUE(result, 4);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "10000001000000000100000001000000", 32);
	dv = bignum_set_hex(NULL, "20000001000000000100000001000000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0x10000001000000000100000001000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "-10000001000000000100000001000000", 33);
	dv = bignum_set_hex(NULL, "20000001000000000100000001000000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "-0x1", 4);
	status += CHECK_VALUE(result, 4);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0x10000000000000000000000000000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "2b000002b000000002b0000002b0000010000001000000000100000001000000", 64);
	dv = bignum_set_hex(NULL, "a000000a000000000a0000000a000000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "0x44cccccccccccccccccccccccccccccc", 34);
	status += CHECK_VALUE(result, 34);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0x90000009000000000900000009000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "-2b000002b000000002b0000002b0000010000001000000000100000001000000", 65);
	dv = bignum_set_hex(NULL, "a000000a000000000a0000000a000000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "-0x44cccccccccccccccccccccccccccccd", 35);
	status += CHECK_VALUE(result, 35);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0x10000001000000000100000001000000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	dd = bignum_set_hex(NULL, "-2b000002b000000002b0000002b0000010000001000000000100000001000000", 65);
	dv = bignum_set_hex(NULL, "ff00000ff00000000ff000000ff00000", 32);
	q = bignum_new(256);
	r = bignum_new(256);

	bignum_divmod(bctx, dd, dv, q, r);

	memset(qhex, 0, 128);
	memset(rhex, 0, 128);

	result = bignum_get_hex(q, qhex, 128);
	status += CHECK_HEX(qhex, "-0x2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2c", 35);
	status += CHECK_VALUE(result, 35);

	result = bignum_get_hex(r, rhex, 128);
	status += CHECK_HEX(rhex, "0xc400000c400000000c4000000c400000", 34);
	status += CHECK_VALUE(result, 34);

	bignum_delete(dd);
	bignum_delete(dv);
	bignum_delete(q);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	bignum_ctx_delete(bctx);

	return status;
}

int32_t bignum_shift_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL;
	char hex[128] = {0};

	// ------------------------------------------------------------------------

	a = bignum_new(256);
	a = bignum_set_hex(a, "10000001000000000100000001000000", 32);
	a = bignum_lshift(a, a, 5);

	memset(hex, 0, 128);
	result = bignum_get_hex(a, hex, 128);

	status += CHECK_HEX(hex, "0x200000020000000002000000020000000", 35);
	status += CHECK_VALUE(result, 35);

	bignum_delete(a);

	// ------------------------------------------------------------------------

	a = bignum_new(256);
	a = bignum_set_hex(a, "10000001000000000100000001000000", 32);
	a = bignum_lshift(a, a, 79);

	memset(hex, 0, 128);
	result = bignum_get_hex(a, hex, 128);

	status += CHECK_HEX(hex, "0x800000080000000008000000080000000000000000000000000", 53);
	status += CHECK_VALUE(result, 53);

	bignum_delete(a);

	// ------------------------------------------------------------------------

	a = bignum_new(256);
	a = bignum_set_hex(a, "10000001000000000100000001000000", 32);
	a = bignum_lshift(a, a, 64);

	memset(hex, 0, 128);
	result = bignum_get_hex(a, hex, 128);

	status += CHECK_HEX(hex, "0x100000010000000001000000010000000000000000000000", 50);
	status += CHECK_VALUE(result, 50);

	bignum_delete(a);

	// ------------------------------------------------------------------------

	a = bignum_new(256);
	a = bignum_set_hex(a, "10000001000000000100000001000000", 32);
	a = bignum_rshift(a, a, 5);

	memset(hex, 0, 128);
	result = bignum_get_hex(a, hex, 128);

	status += CHECK_HEX(hex, "0x800000080000000008000000080000", 32);
	status += CHECK_VALUE(result, 32);

	bignum_delete(a);

	// ------------------------------------------------------------------------

	a = bignum_new(256);
	a = bignum_set_hex(a, "10000001000000000100000001000000", 32);
	a = bignum_rshift(a, a, 79);

	memset(hex, 0, 128);
	result = bignum_get_hex(a, hex, 128);

	status += CHECK_HEX(hex, "0x200000020000", 14);
	status += CHECK_VALUE(result, 14);

	bignum_delete(a);

	// ------------------------------------------------------------------------

	a = bignum_new(256);
	a = bignum_set_hex(a, "10000001000000000100000001000000", 32);
	a = bignum_rshift(a, a, 64);

	memset(hex, 0, 128);
	result = bignum_get_hex(a, hex, 128);

	status += CHECK_HEX(hex, "0x1000000100000000", 18);
	status += CHECK_VALUE(result, 18);

	bignum_delete(a);

	// ------------------------------------------------------------------------

	a = bignum_new(256);
	a = bignum_set_hex(a, "10000001000000000100000001000000", 32);
	a = bignum_rshift(a, a, 150);

	memset(hex, 0, 128);
	result = bignum_get_hex(a, hex, 128);

	status += CHECK_HEX(hex, "0x0", 3);
	status += CHECK_VALUE(result, 3);

	bignum_delete(a);

	// ------------------------------------------------------------------------

	return status;
}

int main()
{
	return bignum_cmp_tests() + bignum_add_tests() + bignum_sub_tests() + bignum_mul_tests() + bignum_div_tests() + bignum_shift_tests();
}
