/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <scan.h>
#include <string.h>
#include "test.h"

uint32_t test_simple(void)
{
	uint32_t status = 0;
	uint32_t result = 0;

	byte_t c1 = 0, c2 = 0;
	uint32_t n = 0;

	result = sscan("", 0, "");
	status += CHECK_RESULT(result, 0);

	result = sscan("", 0, "%c", &c1);
	status += CHECK_RESULT(result, 0);

	result = sscan("a", 1, "%c", &c1);
	status += CHECK_UVALUE(c1, 'a');
	status += CHECK_RESULT(result, 1);

	result = sscan("bc", 2, "%c%c", &c1, &c2);
	status += CHECK_UVALUE(c1, 'b');
	status += CHECK_UVALUE(c2, 'c');
	status += CHECK_RESULT(result, 2);

	result = sscan("de", 2, "%c  %c", &c1, &c2);
	status += CHECK_UVALUE(c1, 'd');
	status += CHECK_UVALUE(c2, 'e');
	status += CHECK_RESULT(result, 2);

	result = sscan("h  i", 4, "%c %c", &c1, &c2);
	status += CHECK_UVALUE(c1, 'h');
	status += CHECK_UVALUE(c2, 'i');
	status += CHECK_RESULT(result, 2);

	result = sscan("jh   gk", 7, "%ch g%c", &c1, &c2);
	status += CHECK_UVALUE(c1, 'j');
	status += CHECK_UVALUE(c2, 'k');
	status += CHECK_RESULT(result, 2);

	result = sscan("lh   gl", 7, "%ch l%c", &c1, &c2);
	status += CHECK_UVALUE(c1, 'l');
	status += CHECK_RESULT(result, 1);

	result = sscan("jh   gk", 7, "%ch g%c%n", &c1, &c2, &n);
	status += CHECK_UVALUE(c1, 'j');
	status += CHECK_UVALUE(c2, 'k');
	status += CHECK_UVALUE(n, 7);
	status += CHECK_RESULT(result, 2);

	result = sscan("jh   gk", 7, "%ch g%c  %n", &c1, &c2, &n);
	status += CHECK_UVALUE(c1, 'j');
	status += CHECK_UVALUE(c2, 'k');
	status += CHECK_UVALUE(n, 7);
	status += CHECK_RESULT(result, 2);

	result = sscan("jh   gk    ", 11, "%ch g%c%n", &c1, &c2, &n);
	status += CHECK_UVALUE(c1, 'j');
	status += CHECK_UVALUE(c2, 'k');
	status += CHECK_UVALUE(n, 7);
	status += CHECK_RESULT(result, 2);

	result = sscan("jh   gk    ", 11, "%ch g%c  %n", &c1, &c2, &n);
	status += CHECK_UVALUE(c1, 'j');
	status += CHECK_UVALUE(c2, 'k');
	status += CHECK_UVALUE(n, 11);
	status += CHECK_RESULT(result, 2);

	return status;
}

uint32_t test_int()
{
	uint32_t status = 0;
	uint32_t result = 0;

	int32_t i = 0, j = 0;
	uint32_t n = 0;

	result = sscan("123", 3, "%d%n", &i, &n);
	status += CHECK_IVALUE(i, 123);
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 1);

	result = sscan("-123", 4, "%d%n", &i, &n);
	status += CHECK_IVALUE(i, -123);
	status += CHECK_UVALUE(n, 4);
	status += CHECK_RESULT(result, 1);

	result = sscan("-123", 4, "%1d%n", &i, &n);
	status += CHECK_IVALUE(i, 0);
	status += CHECK_UVALUE(n, 1);
	status += CHECK_RESULT(result, 1);

	result = sscan("000000000000123", 15, "%d%n", &i, &n);
	status += CHECK_IVALUE(i, 123);
	status += CHECK_UVALUE(n, 15);
	status += CHECK_RESULT(result, 1);

	result = sscan("000000000000123", 15, "%5d%n", &i, &n);
	status += CHECK_IVALUE(i, 0);
	status += CHECK_UVALUE(n, 5);
	status += CHECK_RESULT(result, 1);

	result = sscan("123", 3, "%2d %d%n", &i, &j, &n);
	status += CHECK_IVALUE(i, 12);
	status += CHECK_IVALUE(j, 3);
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 2);

	result = sscan("123", 3, "%2$2d %1$d%3$n", &i, &j, &n);
	status += CHECK_IVALUE(i, 3);
	status += CHECK_IVALUE(j, 12);
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 2);

	result = sscan("000000000000123", 15, "%5d%2d%n", &i, &j, &n);
	status += CHECK_IVALUE(i, 0);
	status += CHECK_IVALUE(j, 0);
	status += CHECK_UVALUE(n, 7);
	status += CHECK_RESULT(result, 2);

	result = sscan("123-56", 6, "%d %d%n", &i, &j, &n);
	status += CHECK_IVALUE(i, 123);
	status += CHECK_IVALUE(j, -56);
	status += CHECK_UVALUE(n, 6);
	status += CHECK_RESULT(result, 2);

	result = sscan("456  -089", 9, "%d %d%n", &i, &j, &n);
	status += CHECK_IVALUE(i, 456);
	status += CHECK_IVALUE(j, -89);
	status += CHECK_UVALUE(n, 9);
	status += CHECK_RESULT(result, 2);

	return status;
}

uint32_t test_uint()
{
	uint32_t status = 0;
	uint32_t result = 0;

	uint32_t u = 0, o = 0, b = 0, x = 0;
	uint32_t n = 0;

	result = sscan("123", 3, "%u%n", &u, &n);
	status += CHECK_IVALUE(u, 123);
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 1);

	result = sscan("000000000000123", 15, "%u%n", &u, &n);
	status += CHECK_IVALUE(u, 123);
	status += CHECK_UVALUE(n, 15);
	status += CHECK_RESULT(result, 1);

	result = sscan("-123", 4, "%u%n", &u, &n);
	status += CHECK_RESULT(result, 0);

	result = sscan("123", 3, "%2u%n", &u, &n);
	status += CHECK_IVALUE(u, 12);
	status += CHECK_UVALUE(n, 2);
	status += CHECK_RESULT(result, 1);

	result = sscan("00010", 5, "%b%n", &b, &n);
	status += CHECK_IVALUE(b, 2);
	status += CHECK_UVALUE(n, 5);
	status += CHECK_RESULT(result, 1);

	result = sscan("1000010", 7, "%b%n", &b, &n);
	status += CHECK_IVALUE(b, 66);
	status += CHECK_UVALUE(n, 7);
	status += CHECK_RESULT(result, 1);

	result = sscan("1000010", 7, "%3b%n", &b, &n);
	status += CHECK_IVALUE(b, 4);
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 1);

	result = sscan("0b1000010", 9, "%b%n", &b, &n);
	status += CHECK_IVALUE(b, 66);
	status += CHECK_UVALUE(n, 9);
	status += CHECK_RESULT(result, 1);

	result = sscan("0b1000010", 9, "%4b%n", &b, &n);
	status += CHECK_IVALUE(b, 2);
	status += CHECK_UVALUE(n, 4);
	status += CHECK_RESULT(result, 1);

	result = sscan("123", 3, "%o%n", &o, &n);
	status += CHECK_IVALUE(o, 83);
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 1);

	result = sscan("000000000000123", 15, "%o%n", &o, &n);
	status += CHECK_IVALUE(o, 83);
	status += CHECK_UVALUE(n, 15);
	status += CHECK_RESULT(result, 1);

	result = sscan("0456", 4, "%o%n", &o, &n);
	status += CHECK_IVALUE(o, 302);
	status += CHECK_UVALUE(n, 4);
	status += CHECK_RESULT(result, 1);

	result = sscan("0o457", 5, "%o%n", &o, &n);
	status += CHECK_IVALUE(o, 303);
	status += CHECK_UVALUE(n, 5);
	status += CHECK_RESULT(result, 1);

	result = sscan("0O455", 5, "%o%n", &o, &n);
	status += CHECK_IVALUE(o, 301);
	status += CHECK_UVALUE(n, 5);
	status += CHECK_RESULT(result, 1);

	result = sscan("0O458", 5, "%2o%n", &o, &n);
	status += CHECK_IVALUE(o, 0);
	status += CHECK_UVALUE(n, 2);
	status += CHECK_RESULT(result, 1);

	result = sscan("-123", 4, "%o%n", &o, &n);
	status += CHECK_RESULT(result, 0);

	result = sscan("789", 3, "%2o%n", &o, &n);
	status += CHECK_IVALUE(o, 7);
	status += CHECK_UVALUE(n, 1);
	status += CHECK_RESULT(result, 1);

	result = sscan("123", 3, "%x%n", &x, &n);
	status += CHECK_IVALUE(x, 291);
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 1);

	result = sscan("000000000000123", 15, "%x%n", &x, &n);
	status += CHECK_IVALUE(x, 291);
	status += CHECK_UVALUE(n, 15);
	status += CHECK_RESULT(result, 1);

	result = sscan("0x45Bf", 6, "%x%n", &x, &n);
	status += CHECK_IVALUE(x, 17855);
	status += CHECK_UVALUE(n, 6);
	status += CHECK_RESULT(result, 1);

	result = sscan("0x45Bf", 6, "%3x%n", &x, &n);
	status += CHECK_IVALUE(x, 4);
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 1);

	result = sscan("0X45cf", 6, "%8x%n", &x, &n);
	status += CHECK_IVALUE(x, 17871);
	status += CHECK_UVALUE(n, 6);
	status += CHECK_RESULT(result, 1);

	result = sscan("0X45df", 6, "%8X%n", &x, &n);
	status += CHECK_IVALUE(x, 17887);
	status += CHECK_UVALUE(n, 6);
	status += CHECK_RESULT(result, 1);

	return status;
}

uint32_t test_char()
{
	uint32_t status = 0;
	uint32_t result = 0;

	byte_t utf8_ch = 0;
	uint16_t utf16_ch = 0;
	uint32_t utf32_ch = 0;

	uint32_t n = 0;

	result = sscan("a", 1, "%c%n", &utf8_ch, &n);
	status += CHECK_UVALUE(utf8_ch, 'a');
	status += CHECK_UVALUE(n, 1);
	status += CHECK_RESULT(result, 1);

	result = sscan("€", 3, "%lc%n", &utf16_ch, &n);
	status += CHECK_UVALUE(utf16_ch, u'€');
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 1);

	result = sscan("€", 3, "%llc%n", &utf32_ch, &n);
	status += CHECK_UVALUE(utf32_ch, U'€');
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 1);

	result = sscan("😊", 4, "%llc%n", &utf32_ch, &n);
	status += CHECK_UVALUE(utf32_ch, U'😊');
	status += CHECK_UVALUE(n, 4);
	status += CHECK_RESULT(result, 1);

	return status;
}

uint32_t test_pointer(void)
{
	uint32_t status = 0;
	uint32_t result = 0;

	uintptr_t p = 0;
	uint32_t n = 0;

	result = sscan("0x22", 4, "%p%n", &p, &n);
	status += CHECK_UVALUE(p, 0x22);
	status += CHECK_UVALUE(n, 4);
	status += CHECK_RESULT(result, 1);

	result = sscan("0x22", 4, "%2p%n", &p, &n);
	status += CHECK_UVALUE(p, 0x0);
	status += CHECK_UVALUE(n, 2);
	status += CHECK_RESULT(result, 1);

	result = sscan("0x22", 4, "%3p%n", &p, &n);
	status += CHECK_UVALUE(p, 0x2);
	status += CHECK_UVALUE(n, 3);
	status += CHECK_RESULT(result, 1);

	result = sscan("0x22", 4, "%4p%n", &p, &n);
	status += CHECK_UVALUE(p, 0x22);
	status += CHECK_UVALUE(n, 4);
	status += CHECK_RESULT(result, 1);

	result = sscan("0x22", 4, "%5p%n", &p, &n);
	status += CHECK_UVALUE(p, 0x22);
	status += CHECK_UVALUE(n, 4);
	status += CHECK_RESULT(result, 1);

	result = sscan("0x22  ", 6, "%5p%n", &p, &n);
	status += CHECK_UVALUE(p, 0x22);
	status += CHECK_UVALUE(n, 4);
	status += CHECK_RESULT(result, 1);

	return status;
}

int main()
{
	return test_simple() + test_int() + test_uint() + test_char() + test_pointer();
}
