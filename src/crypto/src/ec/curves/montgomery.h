/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>

// clang-format off

// Curve-25519
const bn_word_t curve25519_p_words[4] = {0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF};
const bn_word_t curve25519_a_words[1] = {0x0000000000076D06};
const bn_word_t curve25519_b_words[1] = {0x0000000000000001};
const bn_word_t curve25519_n_words[4] = {0x5812631A5CF5D3ED, 0x14DEF9DEA2F79CD6, 0x0000000000000000, 0x1000000000000000};
const bn_word_t curve25519_gx_words[1] = {0x0000000000000009};
const bn_word_t curve25519_gy_words[4] = {0x29E9C5A27ECED3D9, 0x923D4D7E6D7C61B2, 0xE01EDD2C7748D14C, 0x20AE19A1B8A086B4};

// Curve-448
const bn_word_t curve448_p_words[7] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
const bn_word_t curve448_a_words[1] = {0x00000000000262A6};
const bn_word_t curve448_b_words[1] = {0x0000000000000001};
const bn_word_t curve448_n_words[7] = {0x2378C292AB5844F3, 0x216CC2728DC58F55, 0xC44EDB49AED63690, 0xFFFFFFFF7CCA23E9, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF};
const bn_word_t curve448_gx_words[1] = {0x0000000000000005};
const bn_word_t curve448_gy_words[7] = {0x6FD7223D457B5B1A, 0x1312C4B150677AF7, 0xB8027E2346430D21, 0x60F75DC28DF3F6ED, 0xCBAE5D34F55545D0, 0x6C98AB6E58326FCE, 0x7D235D1295F5B1F6};

// clang-format on
