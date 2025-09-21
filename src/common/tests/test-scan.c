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

	char c1 = 0, c2 = 0;

	result = sscan("", 0, "");
	status += CHECK_RESULT(result, 0);

	result = sscan("", 0, "%c");
	status += CHECK_RESULT(result, 0);

	result = sscan("a", 0, "%c", &c1);
	status += CHECK_RESULT(c1, 'a');
	status += CHECK_RESULT(result, 1);

	result = sscan("bc", 0, "%c%c", &c1, &c2);
	status += CHECK_RESULT(c1, 'b');
	status += CHECK_RESULT(c2, 'c');
	status += CHECK_RESULT(result, 2);

	result = sscan("de", 0, "%c  %c", &c1, &c2);
	status += CHECK_RESULT(c1, 'd');
	status += CHECK_RESULT(c2, 'e');
	status += CHECK_RESULT(result, 2);

	result = sscan("f  g", 0, "%c%c", &c1, &c2);
	status += CHECK_RESULT(c1, 'f');
	status += CHECK_RESULT(c2, 'g');
	status += CHECK_RESULT(result, 2);

	result = sscan("h  i", 0, "%c %c", &c1, &c2);
	status += CHECK_RESULT(c1, 'h');
	status += CHECK_RESULT(c2, 'i');
	status += CHECK_RESULT(result, 2);

	result = sscan("jh   gk", 0, "%ch g%c", &c1, &c2);
	status += CHECK_RESULT(c1, 'j');
	status += CHECK_RESULT(c2, 'k');
	status += CHECK_RESULT(result, 2);

	return status;
}

int main()
{
	return 0;
}
