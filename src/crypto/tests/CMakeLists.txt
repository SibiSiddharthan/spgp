#[[
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

add_executable(test-md5 hash/test-md5.c)
target_link_libraries(test-md5 crypto)

add_test(NAME test-md5 COMMAND test-md5)
