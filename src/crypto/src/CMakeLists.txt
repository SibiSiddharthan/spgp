#[[
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

add_library(crypto STATIC 
			hash/md5.c
			hash/sha1.c hash/sha256.c)

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
