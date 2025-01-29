/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_EC_CURVES_EDWARDS_H
#define CRYPTO_EC_CURVES_EDWARDS_H

#include <bignum.h>

// clang-format off

// Edwards-25519
const bn_word_t ed25519_p_words[4] = {0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF};
const bn_word_t ed25519_a_words[4] = {0xFFFFFFFFFFFFFFEC, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF};
const bn_word_t ed25519_d_words[4] = {0x75EB4DCA135978A3, 0x00700A4D4141D8AB, 0x8CC740797779E898, 0x52036CEE2B6FFE73};
const bn_word_t ed25519_n_words[4] = {0x5812631A5CF5D3ED, 0x14DEF9DEA2F79CD6, 0x0000000000000000, 0x1000000000000000};
const bn_word_t ed25519_gx_words[4] = {0xC9562D608F25D51A, 0x692CC7609525A7B2, 0xC0A4E231FDD6DC5C, 0x216936D3CD6E53FE};
const bn_word_t ed25519_gy_words[4] = {0x6666666666666658, 0x6666666666666666, 0x6666666666666666, 0x6666666666666666};

// Edwards-448
const bn_word_t ed448_p_words[7] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
const bn_word_t ed448_a_words[1] = {0x0000000000000001};
const bn_word_t ed448_d_words[7] = {0x243CC32DBAA156B9, 0xD080997058FB61C4, 0x9CCC9C81264CFE9A, 0x809B1DA3412A12E7, 0xAD46157242A50F37, 0xF24F38C29373A2CC, 0xD78B4BDC7F0DAF19};
const bn_word_t ed448_n_words[7] = {0x2378C292AB5844F3, 0x216CC2728DC58F55, 0xC44EDB49AED63690, 0xFFFFFFFF7CCA23E9, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF};
const bn_word_t ed448_gx_words[7] = {0x698713093E9C04FC, 0x9DE732F38496CD11, 0xE21F7787ED697224, 0x0C25A07D728BDC93, 0x1128751AC9296924, 0xAE7C9DF416C792C6, 0x79A70B2B70400553};
const bn_word_t ed448_gy_words[7] = {0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0xFFFFFFFF80000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF};

// clang-format on

uint32_t ec_edwards_point_is_identity(ec_group *eg, ec_point *a);
uint32_t ec_edwards_point_on_curve(ec_group *eg, ec_point *a);

ec_point *ec_edwards_point_double(ec_group *eg, ec_point *r, ec_point *a);
ec_point *ec_edwards_point_add(ec_group *eg, ec_point *r, ec_point *a, ec_point *b);
ec_point *ec_edwards_point_multiply(ec_group *eg, ec_point *r, ec_point *a, bignum_t *n);

uint32_t ec_ed25519_point_encode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size, uint32_t flags);
ec_point *ec_ed25519_point_decode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size);

uint32_t ec_ed448_point_encode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size, uint32_t flags);
ec_point *ec_ed448_point_decode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size);

#endif
