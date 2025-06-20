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
						-std=c23)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
	add_compile_options(/W4
						/wd4098 # 'void' function returning a value
						/wd4244 # Conversion possible loss of data
						/wd4267 # Conversion possible loss of data
						/wd4702 # Unreachable code
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

add_subdirectory(src)
