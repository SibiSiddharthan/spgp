#[[
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

cmake_minimum_required(VERSION 3.15)
project(spgp C)

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
	add_compile_options(-fcolor-diagnostics -fansi-escape-codes
						-Wall -Wextra
						-std=c11)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
	add_compile_options(/W4
						/wd4098 # 'void' function returning a value
						/wd4244 # Conversion possible loss of data
						/wd4267 # Conversion possible loss of data
						/wd4702 # Unreachable code
						/std:c11)
endif()

add_subdirectory(src)
