/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_TEST_H
#define COMMON_TEST_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <float.h>
#include <minmax.h>

uint32_t check_value_string(const char *actual, const char *expected, const char *expression, const char *function, int32_t line)
{
	if (strcmp(actual, expected) != 0)
	{
		printf("Value does not match in %s:%d.\n(%s) -> (%s == %s)\n", function, line, expression, actual, expected);
		return 1;
	}

	return 0;
}

uint32_t check_result(uint32_t actual, uint32_t expected, const char *expression, const char *function, int32_t line)
{
	if (actual != expected)
	{
		printf("Value does not match in %s:%d.\n(%s) -> (%u == %u)\n", function, line, expression, actual, expected);
		return 1;
	}

	return 0;
}

uint32_t check_value_signed(intmax_t actual, intmax_t expected, const char *expression, const char *function, int32_t line)
{
	if (actual != expected)
	{
		printf("Value does not match in %s:%d.\n(%s) -> (%jd == %jd)\n", function, line, expression, actual, expected);
		return 1;
	}

	return 0;
}

uint32_t check_value_unsigned(uintmax_t actual, uintmax_t expected, const char *expression, const char *function, int32_t line)
{
	if (actual != expected)
	{
		printf("Value does not match in %s:%d.\n(%s) -> (%ju == %ju)\n", function, line, expression, actual, expected);
		return 1;
	}

	return 0;
}

uint32_t check_value_double(double actual, double expected, const char *expression, const char *function, int32_t line)
{
	if ((MAX(actual, expected) - MIN(actual, expected)) > DBL_EPSILON)
	{
		printf("Value does not match in %s:%d.\n(%s) -> (%f == %f)\n", function, line, expression, actual, expected);
		return 1;
	}

	return 0;
}

uint32_t check_value_wstring(void *actual, void *expected, size_t size, const char *expression, const char *function, int32_t line)
{
	if (memcmp(actual, expected, size) != 0)
	{
		printf("Value does not match in %s:%d.\n(%s)\n", function, line, expression);
		return 1;
	}

	return 0;
}

#define CHECK_STRING(ACTUAL, EXPECT)  check_value_string(ACTUAL, EXPECT, #ACTUAL " == " #EXPECT, __FUNCTION__, __LINE__)
#define CHECK_WSTRING(ACTUAL, EXPECT) check_value_wstring(ACTUAL, EXPECT, sizeof(EXPECT), #ACTUAL " == " #EXPECT, __FUNCTION__, __LINE__)
#define CHECK_RESULT(ACTUAL, EXPECT)  check_result(ACTUAL, EXPECT, #ACTUAL " == " #EXPECT, __FUNCTION__, __LINE__)
#define CHECK_UVALUE(ACTUAL, EXPECT)  check_value_unsigned(ACTUAL, EXPECT, #ACTUAL " == " #EXPECT, __FUNCTION__, __LINE__)
#define CHECK_IVALUE(ACTUAL, EXPECT)  check_value_signed(ACTUAL, EXPECT, #ACTUAL " == " #EXPECT, __FUNCTION__, __LINE__)
#define CHECK_DOUBLE(ACTUAL, EXPECT)  check_value_double(ACTUAL, EXPECT, #ACTUAL " == " #EXPECT, __FUNCTION__, __LINE__)

#endif
