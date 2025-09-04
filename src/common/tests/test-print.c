/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <print.h>
#include "test.h"

uint32_t test_simple(void)
{
	uint32_t status = 0;

	uint32_t result = 0;
	char buffer[256] = {0};

	result = sprint(buffer, 256, "abcd");

	status += CHECK_STRING(buffer, "abcd");
	status += CHECK_RESULT(result, 4);

	return status;
}

int main()
{
	return test_simple();
}
