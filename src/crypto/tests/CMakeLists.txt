#[[
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

# Function for adding tests
function(crypto_cipher_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} cipher/test-${test}.c)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

function(crypto_hash_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} hash/test-${test}.c)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

function(crypto_mac_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} mac/test-${test}.c)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()


crypto_cipher_tests(
aes
aria
camellia
chacha20
des
twofish
)

crypto_hash_tests(
blake2
md5
ripemd
sha1
sha2
sha3
)

crypto_mac_tests(
hmac
)
