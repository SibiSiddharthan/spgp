/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <print.h>
#include <string.h>
#include "test.h"

uint32_t test_simple(void)
{
	uint32_t status = 0;

	uint32_t result = 0;
	char buffer[256] = {0};

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "");
	status += CHECK_STRING(buffer, "");
	status += CHECK_RESULT(result, 0);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abcd");
	status += CHECK_STRING(buffer, "abcd");
	status += CHECK_RESULT(result, 4);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%%");
	status += CHECK_STRING(buffer, "abc%");
	status += CHECK_RESULT(result, 4);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%%abc");
	status += CHECK_STRING(buffer, "%abc");
	status += CHECK_RESULT(result, 4);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%%%%%%");
	status += CHECK_STRING(buffer, "%%%");
	status += CHECK_RESULT(result, 3);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%");
	status += CHECK_STRING(buffer, "%");
	status += CHECK_RESULT(result, 1);

	memset(buffer, 0, 256);
	result = sprint(NULL, 0, "abcd");
	status += CHECK_RESULT(result, 4);

	return status;
}

uint32_t test_uint(void)
{
	uint32_t status = 0;

	uint32_t result = 0;
	char buffer[256] = {0};

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%u", 10);
	status += CHECK_STRING(buffer, "10");
	status += CHECK_RESULT(result, 2);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%u %u", 10, 100);
	status += CHECK_STRING(buffer, "10 100");
	status += CHECK_RESULT(result, 6);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%1$u %1$u", 10, 100);
	status += CHECK_STRING(buffer, "10 10");
	status += CHECK_RESULT(result, 5);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%.5u", 55);
	status += CHECK_STRING(buffer, "00055");
	status += CHECK_RESULT(result, 5);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%5u", 55);
	status += CHECK_STRING(buffer, "   55");
	status += CHECK_RESULT(result, 5);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%05u", 55);
	status += CHECK_STRING(buffer, "00055");
	status += CHECK_RESULT(result, 5);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%b", 10);
	status += CHECK_STRING(buffer, "1010");
	status += CHECK_RESULT(result, 4);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%b %b", 10, 100);
	status += CHECK_STRING(buffer, "1010 1100100");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%1$b %1$b", 10, 100);
	status += CHECK_STRING(buffer, "1010 1010");
	status += CHECK_RESULT(result, 9);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%.9u", 55);
	status += CHECK_STRING(buffer, "000110111");
	status += CHECK_RESULT(result, 9);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%9u", 55);
	status += CHECK_STRING(buffer, "   110111");
	status += CHECK_RESULT(result, 9);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%09u", 55);
	status += CHECK_STRING(buffer, "000110111");
	status += CHECK_RESULT(result, 9);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%o", 10);
	status += CHECK_STRING(buffer, "12");
	status += CHECK_RESULT(result, 2);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%o %o", 10, 100);
	status += CHECK_STRING(buffer, "12 144");
	status += CHECK_RESULT(result, 6);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%1$o %1$o", 10, 100);
	status += CHECK_STRING(buffer, "12 12");
	status += CHECK_RESULT(result, 5);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%.3o", 55);
	status += CHECK_STRING(buffer, "067");
	status += CHECK_RESULT(result, 5);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%3o", 55);
	status += CHECK_STRING(buffer, " 65");
	status += CHECK_RESULT(result, 3);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%03o", 55);
	status += CHECK_STRING(buffer, "067");
	status += CHECK_RESULT(result, 3);

	return status;
}

uint32_t test_char(void)
{
	uint32_t status = 0;

	uint32_t result = 0;
	char buffer[256] = {0};

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%c", 'd');
	status += CHECK_STRING(buffer, "abcd");
	status += CHECK_RESULT(result, 4);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%c%c", 'd', 'e');
	status += CHECK_STRING(buffer, "abcde");
	status += CHECK_RESULT(result, 5);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%4c%4c", 'd', 'e');
	status += CHECK_STRING(buffer, "abc   d   e");
	status += CHECK_RESULT(result, 11);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%4c%-5c", 'd', 'e');
	status += CHECK_STRING(buffer, "abc   de    ");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%#02.4c", 'd');
	status += CHECK_STRING(buffer, "abc d");
	status += CHECK_RESULT(result, 5);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%lc", L'd');
	status += CHECK_STRING(buffer, "abcd");
	status += CHECK_RESULT(result, 4);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%4lc%-5lc", L'd', L'e');
	status += CHECK_STRING(buffer, "abc   de    ");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%llc", U'😊');
	status += CHECK_STRING(buffer, "abc😊");
	status += CHECK_RESULT(result, 7);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%4llc", U'😊');
	status += CHECK_STRING(buffer, "abc   😊");
	status += CHECK_RESULT(result, 10);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%hc", 'd');
	status += CHECK_STRING(buffer, "abcd");
	status += CHECK_RESULT(result, 4);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%*c%-*c", 4, 'd', 5, 'e');
	status += CHECK_STRING(buffer, "abc   de    ");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%*c%-*.*c", 4, 'd', 5, 6, 'e');
	status += CHECK_STRING(buffer, "abc   de    ");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%2$*1$c%4$-*3$c", 4, 'd', 5, 'e');
	status += CHECK_STRING(buffer, "abc   de    ");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%2$*1$c%4$-*1$c", 4, 'd', 'e');
	status += CHECK_STRING(buffer, "abc   de   ");
	status += CHECK_RESULT(result, 11);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%2$*1$c%3$-*1$.*4$c", 4, 'd', 'e', 5);
	status += CHECK_STRING(buffer, "abc   de   ");
	status += CHECK_RESULT(result, 11);

	return status;
}

uint32_t test_string()
{
	uint32_t status = 0;

	uint32_t result = 0;
	intmax_t out = 0;
	char buffer[256] = {0};

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %s\n", "World");
	status += CHECK_STRING(buffer, "Hello World\n");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %.6s\n", "World");
	status += CHECK_STRING(buffer, "Hello World\n");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %.4s\n", "World");
	status += CHECK_STRING(buffer, "Hello Worl\n");
	status += CHECK_RESULT(result, 11);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %6.3s\n", "World");
	status += CHECK_STRING(buffer, "Hello    Wor\n");
	status += CHECK_RESULT(result, 13);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %.*s\n", 5, "World");
	status += CHECK_STRING(buffer, "Hello World\n");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %2$.*1$s\n", 5, "World");
	status += CHECK_STRING(buffer, "Hello World\n");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %2$.*1$s\n%3$jn", 5, "World", &out);
	status += CHECK_STRING(buffer, "Hello World\n");
	status += CHECK_RESULT(result, 12);
	status += CHECK_RESULT(out, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %ls\n", L"World");
	status += CHECK_STRING(buffer, "Hello World\n");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %.6ls\n", L"World");
	status += CHECK_STRING(buffer, "Hello World\n");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %.4ls\n", L"World");
	status += CHECK_STRING(buffer, "Hello Worl\n");
	status += CHECK_RESULT(result, 11);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %6.3ls\n", L"World");
	status += CHECK_STRING(buffer, "Hello    Wor\n");
	status += CHECK_RESULT(result, 13);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %.*ls\n", 5, L"World");
	status += CHECK_STRING(buffer, "Hello World\n");
	status += CHECK_RESULT(result, 12);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %s\n%jn", "World😊", &out);
	status += CHECK_STRING(buffer, "Hello World😊\n");
	status += CHECK_RESULT(result, 16);
	status += CHECK_RESULT(out, 16);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %ls\n%jn", L"World😊", &out);
	status += CHECK_STRING(buffer, "Hello World😊\n");
	status += CHECK_RESULT(result, 16);
	status += CHECK_RESULT(out, 16);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %ls\n%jn", u"World😊", &out);
	status += CHECK_STRING(buffer, "Hello World😊\n");
	status += CHECK_RESULT(result, 16);
	status += CHECK_RESULT(out, 16);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "Hello %lls\n%jn", U"World😊", &out);
	status += CHECK_STRING(buffer, "Hello World😊\n");
	status += CHECK_RESULT(result, 16);
	status += CHECK_RESULT(out, 16);

	return status;
}

uint32_t test_pointer(void)
{
	uint32_t status = 0;

	uint32_t result = 0;
	void *ptr = (void *)0x800800800;
	char buffer[256] = {0};

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%p", ptr);
	status += CHECK_STRING(buffer, "abc0x0000000800800800");
	status += CHECK_RESULT(result, 21);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%-20p", ptr);
	status += CHECK_STRING(buffer, "abc0x0000000800800800  ");
	status += CHECK_RESULT(result, 23);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "abc%21p", ptr);
	status += CHECK_STRING(buffer, "abc   0x0000000800800800");
	status += CHECK_RESULT(result, 24);

	return status;
}

uint32_t test_result(void)
{
	uint32_t status = 0;

	int32_t out2 = 0;
	int32_t out1 = 0;

	uint32_t result = 0;
	char buffer[256] = {0};

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "%n", &out1);
	status += CHECK_STRING(buffer, "");
	status += CHECK_RESULT(result, 0);
	status += CHECK_RESULT(out1, 0);

	memset(buffer, 0, 256);
	result = sprint(buffer, 256, "a%nbc%c%n", &out1, 'd', &out2);
	status += CHECK_STRING(buffer, "abcd");
	status += CHECK_RESULT(result, 4);
	status += CHECK_RESULT(out1, 1);
	status += CHECK_RESULT(out2, 4);

	return status;
}

int main()
{
	return test_simple() + test_uint() + test_char() + test_string() + test_pointer() + test_result();
}
