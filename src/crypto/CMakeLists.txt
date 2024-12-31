#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

cmake_minimum_required(VERSION 3.15)
project(crypto C)

add_subdirectory(src)

include(CTest)
if(BUILD_TESTING)
	add_subdirectory(tests)
endif()
