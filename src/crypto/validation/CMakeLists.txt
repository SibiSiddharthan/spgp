#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

add_executable(hash-validate src/hash.c)
target_link_libraries(hash-validate crypto io)
