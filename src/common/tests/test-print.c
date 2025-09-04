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

	return status;
}

int main()
{
	return test_simple() + test_char();
}
