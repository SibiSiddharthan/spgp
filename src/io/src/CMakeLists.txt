#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

set(io_src common/io.c common/status.c)

if(WIN32)
	list(APPEND io_src win32/os.c win32/io.c win32/path.c win32/security.c win32/status.c)
else()
	list(APPEND io_src posix/os.c posix/status.c)
endif()

add_library(io STATIC ${io_src})
target_include_directories(io PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)

if(WIN32)
	target_link_libraries(io PUBLIC ntdll)
endif()
