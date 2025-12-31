#[[
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

cmake_minimum_required(VERSION 3.15)
project(common C)

add_library(common src/buffer.c src/convert.c src/print.c src/scan.c src/varargs.h)

#tests
if(BUILD_TESTING)
include(CTest)

	add_executable(test-print tests/test-print.c)
	target_link_libraries(test-print common)
	add_test(NAME test-print COMMAND test-print WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

	add_executable(test-scan tests/test-scan.c)
	target_link_libraries(test-scan common)
	add_test(NAME test-scan COMMAND test-scan WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()