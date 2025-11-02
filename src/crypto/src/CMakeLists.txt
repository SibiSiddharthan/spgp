#[[
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
]]

set(bignum_asm 
bignum/asm/generic/cmp.c
bignum/asm/generic/add.c
bignum/asm/generic/sub.c
bignum/asm/generic/mul.c
bignum/asm/generic/div.c
)

add_library(crypto STATIC
#armor
armor/base64.c
#bignum
bignum/bignum.c
bignum/ctx.c
bignum/bytes.c
bignum/cmp.c
bignum/addsub.c
bignum/mul.c
bignum/mod.c
bignum/divmod.c
bignum/shift.c
bignum/gcd.c
bignum/lcm.c
bignum/prime.c
bignum/rand.c
${bignum_asm}
#ec
ec/ec.c
ec/point.c
ec/key.c
ec/oid.c
ec/prime.c
ec/edwards.c
ec/x25519.c
ec/x448.c
#cipher
cipher/aes.c
cipher/aria.c
cipher/blowfish.c
cipher/camellia.c
cipher/cast5.c
cipher/chacha20.c
cipher/des.c
cipher/idea.c
cipher/twofish.c
cipher/cipher.c
cipher/aead/ccm.c
cipher/aead/eax.c
cipher/aead/gcm.c
cipher/aead/ocb.c
cipher/aead/siv.c
cipher/aead/kw.c
cipher/modes/ecb.c
cipher/modes/cbc.c
cipher/modes/cfb.c
cipher/modes/ofb.c
cipher/modes/ctr.c
#dh
dh/dh.c
#hash
hash/md5.c hash/ripemd.c
hash/sha1.c hash/sha256.c hash/sha512.c hash/sha3.c
hash/shake.c
hash/blake2.c
hash/hash.c
#kas
kas/dh.c
kas/mqv.c
#kdf
kdf/argon2.c
kdf/pbkdf2.c
kdf/scrypt.c
kdf/hkdf.c
kdf/kdf.c
#mac
mac/cmac.c
mac/hmac.c
mac/kmac.c
#public-key
public-key/rsa.c
# rand
rand/drbg.c
rand/ctr-drbg.c
rand/hash-drbg.c
rand/hmac-drbg.c
#signature
signature/dsa.c
signature/ecdsa.c
signature/eddsa.c
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|i[3-6]86|AMD64)$")
	
	# Add CPU entropy source for x86_64
	target_sources(crypto PRIVATE rand/entropy/entropy-x86.c)

	if(CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "GNU")
		set_source_files_properties(rand/entropy/entropy-x86.c PROPERTIES COMPILE_FLAGS "-mrdseed")
	endif()
#elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm|aarch64)")
else()
	
	if(WIN32)
		target_sources(crypto PRIVATE rand/entropy/entropy-windows.c)
	else()
		target_sources(crypto PRIVATE rand/entropy/entropy-posix.c)
	endif()

endif()

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
