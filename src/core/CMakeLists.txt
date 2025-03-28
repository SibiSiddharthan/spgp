#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

add_library(pgp OBJECT
			lib/armor.c
			lib/base64.c
			lib/crc24.c
			lib/mpi.c
			lib/crypto.c
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
target_link_libraries(pgp crypto)

add_executable(spgp app/argparse.c app/spgp.c)
target_include_directories(spgp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/app)
target_link_libraries(spgp pgp crypto io)
set_target_properties(spgp PROPERTIES RUNTIME_OUTPUT_NAME "spgp")
