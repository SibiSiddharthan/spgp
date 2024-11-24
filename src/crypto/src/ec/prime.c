/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <bignum.h>
#include <ec.h>

// NIST P-192
bn_word_t nist_p192_p_words[3] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF};
bn_word_t nist_p192_a_words[3] = {0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF};
bn_word_t nist_p192_b_words[3] = {0xFEB8DEECC146B9B1, 0x0FA7E9AB72243049, 0xFEB8DEECC146B9B1};
bn_word_t nist_p192_gx_words[3] = {0xF4FF0AFD82FF1012, 0x7CBF20EB43A18800, 0x188DA80EB03090F6};
bn_word_t nist_p192_gy_words[3] = {0x73F977A11E794811, 0x631011ED6B24CDD5, 0x07192B95FFC8DA78};

const bignum_t nist_p192_p = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_p_words};
const bignum_t nist_p192_a = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_a_words};
const bignum_t nist_p192_b = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_b_words};
const bignum_t nist_p192_gx = {.bits = 192, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_gx_words};
const bignum_t nist_p192_gy = {.bits = 187, .flags = 0, .resize = 0, .sign = 1, .size = 24, .words = nist_p192_gy_words};

const ec_prime_curve ec_nist_p192 = {.p = &nist_p192_p, .a = &nist_p192_a, .b = &nist_p192_b, .gx = &nist_p192_gx, .gy = &nist_p192_gy};

