#[[
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

add_library(crypto STATIC
#cipher
cipher/aes.c
cipher/camellia.c
#hash
hash/md5.c hash/ripemd.c
hash/sha1.c hash/sha256.c hash/sha512.c hash/sha3.c
hash/blake2.c)

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
