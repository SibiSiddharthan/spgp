#[[
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

add_library(spgp OBJECT 
			armor.c armor.h
			base64.c base64.h
			crc24.c crc24.h
			mpi.c mpi.h
			)

target_include_directories(spgp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(spgp crypto)
