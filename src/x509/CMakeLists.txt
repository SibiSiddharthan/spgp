#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

cmake_minimum_required(VERSION 3.15)
project(x509 C)

add_library(x509 src/asn1.c)
target_include_directories(x509 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
