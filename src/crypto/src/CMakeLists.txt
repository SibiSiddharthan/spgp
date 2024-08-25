#[[
   Copyright (c) 2024 Sibi Siddharthan

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
bignum/prime.c
bignum/rand.c
${bignum_asm}
#cipher
cipher/aes.c
cipher/aria.c
cipher/camellia.c
cipher/chacha20.c
cipher/des.c
cipher/twofish.c
cipher/cipher.c
cipher/aead/ccm.c
cipher/aead/eax.c
cipher/aead/gcm.c
cipher/aead/ocb.c
cipher/aead/kw.c
cipher/modes/ecb.c
cipher/modes/cbc.c
cipher/modes/cfb.c
cipher/modes/ofb.c
cipher/modes/ctr.c
#hash
hash/md5.c hash/ripemd.c
hash/sha1.c hash/sha256.c hash/sha512.c hash/sha3.c
hash/shake.c
hash/blake2.c
hash/hash.c
#kdf
kdf/pbkdf2.c
kdf/scrypt.c
#mac
mac/cmac.c
mac/hmac.c
mac/kmac.c
#public-key
public-key/rsa.c
# rand
rand/entropy.c
rand/drbg.c
rand/ctr-drbg.c
rand/hash-drbg.c
rand/hmac-drbg.c
#signature
signature/dsa.c
)

set_source_files_properties(rand/entropy.c PROPERTIES COMPILE_FLAGS "-mrdseed")

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
