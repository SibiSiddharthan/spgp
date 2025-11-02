#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

add_library(pgp STATIC
			lib/armor.c
			lib/crc24.c
			lib/mpi.c
			lib/crypto.c
			lib/error.c
			lib/packet.c
			lib/packets.c
			lib/print.c
			lib/key.c
			lib/s2k.c
			lib/seipd.c
			lib/session.c
			lib/signature.c
			lib/stream.c
			)

target_include_directories(pgp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(pgp crypto common)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	target_compile_definitions(pgp PUBLIC PGP_DEBUG=1)
endif()

add_executable(spgp 
app/spgp.c app/argparse.c app/io.c app/keyring.c app/misc.c app/packets.c app/preferences.c app/encrypt.c app/sign.c app/generate.c)

target_include_directories(spgp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/app)
target_link_libraries(spgp pgp crypto common io)
set_target_properties(spgp PROPERTIES RUNTIME_OUTPUT_NAME "spgp")
set_target_properties(spgp PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
