#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

add_library(spgp OBJECT 
			argparse.c argparse.c
			armor.c armor.h
			base64.c base64.h
			crc24.c crc24.h
			mpi.c mpi.h
			crypto.h crypto.c
			packet.c packet.h
			packets.c print.c
			key.c key.h
			s2k.c s2k.h
			seipd.c seipd.h
			session.c session.h
			signature.c signature.h
			stream.c stream.h
			)

target_include_directories(spgp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(spgp crypto)

add_executable(spgp-main spgp.c)
target_link_libraries(spgp-main spgp crypto)
set_target_properties(spgp-main PROPERTIES RUNTIME_OUTPUT_NAME "spgp")
