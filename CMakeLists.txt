#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

cmake_minimum_required(VERSION 3.15)
project(spgp C)

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
	add_compile_options(-fcolor-diagnostics -fansi-escape-codes
						-Wall -Wextra
						-Wno-cast-function-type-mismatch
						-std=c23)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
	add_compile_options(-fdiagnostics-color
						-Wall -Wextra
						-Wstringop-overflow=0
						-Wno-cast-function-type
						-Wno-type-limits
						-std=c2x)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
	add_compile_options(/W4
						/wd4018 # '<': signed/unsigned mismatch
						/wd4098 # 'void' function returning a value
						/wd4146 # unary minus operator applied to unsigned type
						/wd4244 # conversion possible loss of data
						/wd4267 # conversion possible loss of data
						/wd4334 # '<<': result of 32-bit shift implicitly converted to 64 bits
						/wd4389 # '==': signed/unsigned mismatch
						/wd4702 # unreachable code
						/std:c17)
endif()

option(ENABLE_ASAN "Use address sanitizer" OFF)

if(ENABLE_ASAN)

	if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
		add_compile_options(-fsanitize=address)
		add_link_options(-fsanitize=address)
		if(WIN32)
			add_link_options(-Xlinker /ignore:4217)
		endif()
	endif()

	if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
		add_compile_options(-fsanitize=address)
		add_link_options(-fsanitize=address)
	endif()

	if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
		add_compile_options(/fsanitize=address)
		add_link_options(/incremental:no)
	endif()

endif()

if(NOT WIN32)
	add_compile_definitions(_POSIX_C_SOURCE=201709L)
endif()

add_subdirectory(src)
