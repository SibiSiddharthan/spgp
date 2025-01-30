/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_EC_CURVES_EDWARDS_H
#define CRYPTO_EC_CURVES_EDWARDS_H

#include <bignum.h>
#include <ec.h>

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
const bn_word_t ed448_d_words[7] = {0xFFFFFFFFFFFF6756, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
const bn_word_t ed448_n_words[7] = {0x2378C292AB5844F3, 0x216CC2728DC58F55, 0xC44EDB49AED63690, 0xFFFFFFFF7CCA23E9, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF};
const bn_word_t ed448_gx_words[7] = {0x2626A82BC70CC05E, 0x433B80E18B00938E, 0x12AE1AF72AB66511, 0xEA6DE324A3D3A464, 0x9E146570470F1767, 0x221D15A622BF36DA, 0x4F1970C66BED0DED};
const bn_word_t ed448_gy_words[7] = {0x9808795BF230FA14, 0xFDBD132C4ED7C8AD, 0x3AD3FF1CE67C39C4, 0x87789C1E05A0C2D7, 0x4BEA73736CA39840, 0x8876203756C9C762, 0x693F46716EB6BC24};

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
