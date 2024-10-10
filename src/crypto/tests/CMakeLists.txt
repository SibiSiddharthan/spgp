#[[
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

# Function for adding tests
function(crypto_bignum_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} bignum/test-${test}.c)
		target_include_directories(test-${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

function(crypto_cipher_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} cipher/test-${test}.c)
		target_include_directories(test-${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

function(crypto_hash_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} hash/test-${test}.c)
		target_include_directories(test-${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

function(crypto_kdf_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} kdf/test-${test}.c)
		target_include_directories(test-${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

function(crypto_mac_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} mac/test-${test}.c)
		target_include_directories(test-${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

function(crypto_rand_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} rand/test-${test}.c)
		target_include_directories(test-${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

function(crypto_signature_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} signature/test-${test}.c)
		target_include_directories(test-${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

crypto_bignum_tests(
arithmetic
basic
mod
gcd
)

crypto_cipher_tests(
aes
aria
camellia
chacha20
des
twofish

# modes
ecb
cbc
cfb
ofb
ctr

#aead
eax
gcm
ccm
kw
)

crypto_hash_tests(
blake2
md5
ripemd
sha1
sha2
sha3
shake
)

crypto_kdf_tests(
kdf
hkdf
pbkdf2
scrypt
)

crypto_mac_tests(
cmac
hmac
kmac
)

crypto_rand_tests(
drbg
)

crypto_signature_tests(
dsa
rsa-sig
)
