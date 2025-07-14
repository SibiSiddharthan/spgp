#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

cmake_minimum_required(VERSION 3.15)
project(tls C)

if(WIN32)
	add_executable(tls-tester src/tester.c)
	target_include_directories(tls-tester PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
	set_target_properties(tls-tester PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()
