#[[
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

# Function for adding tests
function(crypto_hash_tests ...)
	foreach(test ${ARGV})
		add_executable(test-${test} hash/test-${test}.c)
		target_link_libraries(test-${test} crypto)
		add_test(NAME test-${test} COMMAND test-${test} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	endforeach()
endfunction()

crypto_hash_tests(
md5
ripemd
sha1
)
