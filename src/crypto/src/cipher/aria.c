/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <aria.h>
#include <byteswap.h>

// See RFC 5794: A Description of the ARIA Encryption Algorithm

#define ARIA128_ROUNDS 12
#define ARIA192_ROUNDS 14
#define ARIA256_ROUNDS 16

// Key Constants
static const byte_t C1[16] = {0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94, 0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0};
static const byte_t C2[16] = {0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20, 0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0};
static const byte_t C3[16] = {0xdb, 0x92, 0x37, 0x1d, 0x21, 0x26, 0xe9, 0x70, 0x03, 0x24, 0x97, 0x75, 0x04, 0xe8, 0xc9, 0x0e};

// S-Box Data
// clang-format off
static const byte_t SB1[256] =
{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const byte_t SB2[256] =
{
	0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
	0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
	0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
	0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
	0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
	0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
	0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
	0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
	0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
	0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
	0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
	0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
	0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
	0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
	0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
	0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81
};

static const byte_t SB3[256] =
{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const byte_t SB4[256] =
{
	0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c,
	0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d,
	0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d,
	0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed,
	0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b,
	0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce,
	0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9,
	0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41,
	0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a,
	0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7,
	0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc,
	0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5,
	0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45,
	0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d,
	0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3,
	0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60
};
// clang-format on

// r = x ^ y
static inline void XOR128(byte_t r[16], byte_t x[16], byte_t y[16])
{
	uint64_t *rp = (uint64_t *)r;
	uint64_t *xp = (uint64_t *)x;
	uint64_t *yp = (uint64_t *)y;

	rp[0] = xp[0] ^ yp[0];
	rp[1] = xp[1] ^ yp[1];
}

#define ROTR128_19(Y, X)                 \
	{                                    \
		Y[0] = X[14] >> 3 | X[13] << 5;  \
		Y[1] = X[15] >> 3 | X[14] << 5;  \
		Y[2] = X[0] >> 3 | X[15] << 5;   \
		Y[3] = X[1] >> 3 | X[0] << 5;    \
		Y[4] = X[2] >> 3 | X[1] << 5;    \
		Y[5] = X[3] >> 3 | X[2] << 5;    \
		Y[6] = X[4] >> 3 | X[3] << 5;    \
		Y[7] = X[5] >> 3 | X[4] << 5;    \
		Y[8] = X[6] >> 3 | X[5] << 5;    \
		Y[9] = X[7] >> 3 | X[6] << 5;    \
		Y[10] = X[8] >> 3 | X[7] << 5;   \
		Y[11] = X[9] >> 3 | X[8] << 5;   \
		Y[12] = X[10] >> 3 | X[9] << 5;  \
		Y[13] = X[11] >> 3 | X[10] << 5; \
		Y[14] = X[12] >> 3 | X[11] << 5; \
		Y[15] = X[13] >> 3 | X[12] << 5; \
	}

#define ROTR128_31(Y, X)                 \
	{                                    \
		Y[0] = X[13] >> 7 | X[12] << 1;  \
		Y[1] = X[14] >> 7 | X[13] << 1;  \
		Y[2] = X[15] >> 7 | X[14] << 1;  \
		Y[3] = X[0] >> 7 | X[15] << 1;   \
		Y[4] = X[1] >> 7 | X[0] << 1;    \
		Y[5] = X[2] >> 7 | X[1] << 1;    \
		Y[6] = X[3] >> 7 | X[2] << 1;    \
		Y[7] = X[4] >> 7 | X[3] << 1;    \
		Y[8] = X[5] >> 7 | X[4] << 1;    \
		Y[9] = X[6] >> 7 | X[5] << 1;    \
		Y[10] = X[7] >> 7 | X[6] << 1;   \
		Y[11] = X[8] >> 7 | X[7] << 1;   \
		Y[12] = X[9] >> 7 | X[8] << 1;   \
		Y[13] = X[10] >> 7 | X[9] << 1;  \
		Y[14] = X[11] >> 7 | X[10] << 1; \
		Y[15] = X[12] >> 7 | X[11] << 1; \
	}

#define ROTL128_19(Y, X)                 \
	{                                    \
		Y[0] = X[3] >> 5 | X[2] << 3;    \
		Y[1] = X[4] >> 5 | X[3] << 3;    \
		Y[2] = X[5] >> 5 | X[4] << 3;    \
		Y[3] = X[6] >> 5 | X[5] << 3;    \
		Y[4] = X[7] >> 5 | X[6] << 3;    \
		Y[5] = X[8] >> 5 | X[7] << 3;    \
		Y[6] = X[9] >> 5 | X[8] << 3;    \
		Y[7] = X[10] >> 5 | X[9] << 3;   \
		Y[8] = X[11] >> 5 | X[10] << 3;  \
		Y[9] = X[12] >> 5 | X[11] << 3;  \
		Y[10] = X[13] >> 5 | X[12] << 3; \
		Y[11] = X[14] >> 5 | X[13] << 3; \
		Y[12] = X[15] >> 5 | X[14] << 3; \
		Y[13] = X[0] >> 5 | X[15] << 3;  \
		Y[14] = X[1] >> 5 | X[0] << 3;   \
		Y[15] = X[2] >> 5 | X[1] << 3;   \
	}

#define ROTL128_31(Y, X)                 \
	{                                    \
		Y[0] = X[4] >> 1 | X[3] << 7;    \
		Y[1] = X[5] >> 1 | X[4] << 7;    \
		Y[2] = X[6] >> 1 | X[5] << 7;    \
		Y[3] = X[7] >> 1 | X[6] << 7;    \
		Y[4] = X[8] >> 1 | X[7] << 7;    \
		Y[5] = X[9] >> 1 | X[8] << 7;    \
		Y[6] = X[10] >> 1 | X[9] << 7;   \
		Y[7] = X[11] >> 1 | X[10] << 7;  \
		Y[8] = X[12] >> 1 | X[11] << 7;  \
		Y[9] = X[13] >> 1 | X[12] << 7;  \
		Y[10] = X[14] >> 1 | X[13] << 7; \
		Y[11] = X[15] >> 1 | X[14] << 7; \
		Y[12] = X[0] >> 1 | X[15] << 7;  \
		Y[13] = X[1] >> 1 | X[0] << 7;   \
		Y[14] = X[2] >> 1 | X[1] << 7;   \
		Y[15] = X[3] >> 1 | X[2] << 7;   \
	}

#define ROTL128_61(Y, X)                \
	{                                   \
		Y[0] = X[8] >> 3 | X[7] << 5;   \
		Y[1] = X[9] >> 3 | X[8] << 5;   \
		Y[2] = X[10] >> 3 | X[9] << 5;  \
		Y[3] = X[11] >> 3 | X[10] << 5; \
		Y[4] = X[12] >> 3 | X[11] << 5; \
		Y[5] = X[13] >> 3 | X[12] << 5; \
		Y[6] = X[14] >> 3 | X[13] << 5; \
		Y[7] = X[15] >> 3 | X[14] << 5; \
		Y[8] = X[0] >> 3 | X[15] << 5;  \
		Y[9] = X[1] >> 3 | X[0] << 5;   \
		Y[10] = X[2] >> 3 | X[1] << 5;  \
		Y[11] = X[3] >> 3 | X[2] << 5;  \
		Y[12] = X[4] >> 3 | X[3] << 5;  \
		Y[13] = X[5] >> 3 | X[4] << 5;  \
		Y[14] = X[6] >> 3 | X[5] << 5;  \
		Y[15] = X[7] >> 3 | X[6] << 5;  \
	}

#if 0
#	define XOR_ROTR19(R, X, Y) \
		{                       \
			ROTR128_19(R, Y);   \
			XOR128(R, R, X);    \
		}

// R = X ^ (Y >>> 31)
#	define XOR_ROTR31(R, X, Y) \
		{                       \
			ROTR128_31(R, Y);   \
			XOR128(R, R, X);    \
		}

// R = X ^ (Y <<< 19)
#	define XOR_ROTL19(R, X, Y) \
		{                       \
			ROTL128_19(R, Y);   \
			XOR128(R, R, X);    \
		}

// R = X ^ (Y <<< 31)
#	define XOR_ROTL31(R, X, Y) \
		{                       \
			ROTL128_31(R, Y);   \
			XOR128(R, R, X);    \
		}

// R = X ^ (Y <<< 61)
#	define XOR_ROTL61(R, X, Y) \
		{                       \
			ROTL128_61(R, Y);   \
			XOR128(R, R, X);    \
		}
#endif

// r = x ^ (y >>> 19)
static inline void XOR_ROTR19(byte_t r[16], byte_t x[16], byte_t y[16])
{
	uint64_t t0, t1;
	uint64_t *rp = (uint64_t *)r;
	uint64_t *xp = (uint64_t *)x;
	uint64_t *yp = (uint64_t *)y;

	t0 = BSWAP_64(yp[0]);
	t1 = BSWAP_64(yp[1]);

	rp[0] = (t0 >> 19 | t1 << 45);
	rp[1] = (t1 >> 19 | t0 << 45);

	rp[0] = BSWAP_64(rp[0]);
	rp[1] = BSWAP_64(rp[1]);

	rp[0] ^= xp[0];
	rp[1] ^= xp[1];
}

// r = x ^ (y >>> 31)
static inline void XOR_ROTR31(byte_t r[16], byte_t x[16], byte_t y[16])
{
	uint64_t t0, t1;
	uint64_t *rp = (uint64_t *)r;
	uint64_t *xp = (uint64_t *)x;
	uint64_t *yp = (uint64_t *)y;

	t0 = BSWAP_64(yp[0]);
	t1 = BSWAP_64(yp[1]);

	rp[0] = (t0 >> 31 | t1 << 33);
	rp[1] = (t1 >> 31 | t0 << 33);

	rp[0] = BSWAP_64(rp[0]);
	rp[1] = BSWAP_64(rp[1]);

	rp[0] ^= xp[0];
	rp[1] ^= xp[1];
}

// r = x ^ (y <<< 19)
static inline void XOR_ROTL19(byte_t r[16], byte_t x[16], byte_t y[16])
{
	uint64_t t0, t1;
	uint64_t *rp = (uint64_t *)r;
	uint64_t *xp = (uint64_t *)x;
	uint64_t *yp = (uint64_t *)y;

	t0 = BSWAP_64(yp[0]);
	t1 = BSWAP_64(yp[1]);

	rp[0] = (t0 << 19 | t1 >> 45);
	rp[1] = (t1 << 19 | t0 >> 45);

	rp[0] = BSWAP_64(rp[0]);
	rp[1] = BSWAP_64(rp[1]);

	rp[0] ^= xp[0];
	rp[1] ^= xp[1];
}

// r = x ^ (y <<< 31)
static inline void XOR_ROTL31(byte_t r[16], byte_t x[16], byte_t y[16])
{
	uint64_t t0, t1;
	uint64_t *rp = (uint64_t *)r;
	uint64_t *xp = (uint64_t *)x;
	uint64_t *yp = (uint64_t *)y;

	t0 = BSWAP_64(yp[0]);
	t1 = BSWAP_64(yp[1]);

	rp[0] = (t0 << 31 | t1 >> 33);
	rp[1] = (t1 << 31 | t0 >> 33);

	rp[0] = BSWAP_64(rp[0]);
	rp[1] = BSWAP_64(rp[1]);

	rp[0] ^= xp[0];
	rp[1] ^= xp[1];
}

// r = x ^ (y <<< 61)
static inline void XOR_ROTL61(byte_t r[16], byte_t x[16], byte_t y[16])
{
	uint64_t t0, t1;
	uint64_t *rp = (uint64_t *)r;
	uint64_t *xp = (uint64_t *)x;
	uint64_t *yp = (uint64_t *)y;

	t0 = BSWAP_64(yp[0]);
	t1 = BSWAP_64(yp[1]);

	rp[0] = (t0 << 61 | t1 >> 3);
	rp[1] = (t1 << 61 | t0 >> 3);

	rp[0] = BSWAP_64(rp[0]);
	rp[1] = BSWAP_64(rp[1]);

	rp[0] ^= xp[0];
	rp[1] ^= xp[1];
}

static inline void A(byte_t out[16], byte_t in[16])
{
	out[0] = in[3] ^ in[4] ^ in[6] ^ in[8] ^ in[9] ^ in[13] ^ in[14];
	out[1] = in[2] ^ in[5] ^ in[7] ^ in[8] ^ in[9] ^ in[12] ^ in[15];
	out[2] = in[1] ^ in[4] ^ in[6] ^ in[10] ^ in[11] ^ in[12] ^ in[15];
	out[3] = in[0] ^ in[5] ^ in[7] ^ in[10] ^ in[11] ^ in[13] ^ in[14];
	out[4] = in[0] ^ in[2] ^ in[5] ^ in[8] ^ in[11] ^ in[14] ^ in[15];
	out[5] = in[1] ^ in[3] ^ in[4] ^ in[9] ^ in[10] ^ in[14] ^ in[15];
	out[6] = in[0] ^ in[2] ^ in[7] ^ in[9] ^ in[10] ^ in[12] ^ in[13];
	out[7] = in[1] ^ in[3] ^ in[6] ^ in[8] ^ in[11] ^ in[12] ^ in[13];
	out[8] = in[0] ^ in[1] ^ in[4] ^ in[7] ^ in[10] ^ in[13] ^ in[15];
	out[9] = in[0] ^ in[1] ^ in[5] ^ in[6] ^ in[11] ^ in[12] ^ in[14];
	out[10] = in[2] ^ in[3] ^ in[5] ^ in[6] ^ in[8] ^ in[13] ^ in[15];
	out[11] = in[2] ^ in[3] ^ in[4] ^ in[7] ^ in[9] ^ in[12] ^ in[14];
	out[12] = in[1] ^ in[2] ^ in[6] ^ in[7] ^ in[9] ^ in[11] ^ in[12];
	out[13] = in[0] ^ in[3] ^ in[6] ^ in[7] ^ in[8] ^ in[10] ^ in[13];
	out[14] = in[0] ^ in[3] ^ in[4] ^ in[5] ^ in[9] ^ in[11] ^ in[14];
	out[15] = in[1] ^ in[2] ^ in[4] ^ in[5] ^ in[8] ^ in[10] ^ in[15];
}

static inline void SL1(byte_t state[16])
{
	state[0] = SB1[state[0]];
	state[1] = SB2[state[1]];
	state[2] = SB3[state[2]];
	state[3] = SB4[state[3]];
	state[4] = SB1[state[4]];
	state[5] = SB2[state[5]];
	state[6] = SB3[state[6]];
	state[7] = SB4[state[7]];
	state[8] = SB1[state[8]];
	state[9] = SB2[state[9]];
	state[10] = SB3[state[10]];
	state[11] = SB4[state[11]];
	state[12] = SB1[state[12]];
	state[13] = SB2[state[13]];
	state[14] = SB3[state[14]];
	state[15] = SB4[state[15]];
}

static inline void SL2(byte_t state[16])
{
	state[0] = SB3[state[0]];
	state[1] = SB4[state[1]];
	state[2] = SB1[state[2]];
	state[3] = SB2[state[3]];
	state[4] = SB3[state[4]];
	state[5] = SB4[state[5]];
	state[6] = SB1[state[6]];
	state[7] = SB2[state[7]];
	state[8] = SB3[state[8]];
	state[9] = SB4[state[9]];
	state[10] = SB1[state[10]];
	state[11] = SB2[state[11]];
	state[12] = SB3[state[12]];
	state[13] = SB4[state[13]];
	state[14] = SB1[state[14]];
	state[15] = SB2[state[15]];
}

static inline void FO(byte_t out[16], byte_t in[16], byte_t key[16])
{
	byte_t temp[16];

	XOR128(temp, in, key);
	SL1(temp);
	A(out, temp);
}

static inline void FE(byte_t out[16], byte_t in[16], byte_t key[16])
{
	byte_t temp[16];

	XOR128(temp, in, key);
	SL2(temp);
	A(out, temp);
}

void aria128_encrypt_block(aria_key *key, byte_t plaintext[ARIA_BLOCK_SIZE], byte_t ciphertext[ARIA_BLOCK_SIZE])
{
	byte_t state[ARIA_BLOCK_SIZE];

	memcpy(state, plaintext, ARIA_BLOCK_SIZE);

	FO(state, state, key->encryption_round_key[0]);  // Round 1
	FE(state, state, key->encryption_round_key[1]);  // Round 2
	FO(state, state, key->encryption_round_key[2]);  // Round 3
	FE(state, state, key->encryption_round_key[3]);  // Round 4
	FO(state, state, key->encryption_round_key[4]);  // Round 5
	FE(state, state, key->encryption_round_key[5]);  // Round 6
	FO(state, state, key->encryption_round_key[6]);  // Round 7
	FE(state, state, key->encryption_round_key[7]);  // Round 8
	FO(state, state, key->encryption_round_key[8]);  // Round 9
	FE(state, state, key->encryption_round_key[9]);  // Round 10
	FO(state, state, key->encryption_round_key[10]); // Round 11

	// Round 12
	XOR128(state, state, key->encryption_round_key[11]);
	SL2(state);
	XOR128(state, state, key->encryption_round_key[12]);

	memcpy(ciphertext, state, ARIA_BLOCK_SIZE);
}

void aria128_decrypt_block(aria_key *key, byte_t ciphertext[ARIA_BLOCK_SIZE], byte_t plaintext[ARIA_BLOCK_SIZE])
{
	byte_t state[ARIA_BLOCK_SIZE];

	memcpy(state, ciphertext, ARIA_BLOCK_SIZE);

	FO(state, state, key->decryption_round_key[0]);  // Round 1
	FE(state, state, key->decryption_round_key[1]);  // Round 2
	FO(state, state, key->decryption_round_key[2]);  // Round 3
	FE(state, state, key->decryption_round_key[3]);  // Round 4
	FO(state, state, key->decryption_round_key[4]);  // Round 5
	FE(state, state, key->decryption_round_key[5]);  // Round 6
	FO(state, state, key->decryption_round_key[6]);  // Round 7
	FE(state, state, key->decryption_round_key[7]);  // Round 8
	FO(state, state, key->decryption_round_key[8]);  // Round 9
	FE(state, state, key->decryption_round_key[9]);  // Round 10
	FO(state, state, key->decryption_round_key[10]); // Round 11

	// Round 12
	XOR128(state, state, key->decryption_round_key[11]);
	SL2(state);
	XOR128(state, state, key->decryption_round_key[12]);

	memcpy(plaintext, state, ARIA_BLOCK_SIZE);
}

void aria192_encrypt_block(aria_key *key, byte_t plaintext[ARIA_BLOCK_SIZE], byte_t ciphertext[ARIA_BLOCK_SIZE])
{
	byte_t state[ARIA_BLOCK_SIZE];

	memcpy(state, plaintext, ARIA_BLOCK_SIZE);

	FO(state, state, key->encryption_round_key[0]);  // Round 1
	FE(state, state, key->encryption_round_key[1]);  // Round 2
	FO(state, state, key->encryption_round_key[2]);  // Round 3
	FE(state, state, key->encryption_round_key[3]);  // Round 4
	FO(state, state, key->encryption_round_key[4]);  // Round 5
	FE(state, state, key->encryption_round_key[5]);  // Round 6
	FO(state, state, key->encryption_round_key[6]);  // Round 7
	FE(state, state, key->encryption_round_key[7]);  // Round 8
	FO(state, state, key->encryption_round_key[8]);  // Round 9
	FE(state, state, key->encryption_round_key[9]);  // Round 10
	FO(state, state, key->encryption_round_key[10]); // Round 11
	FE(state, state, key->encryption_round_key[11]); // Round 12
	FO(state, state, key->encryption_round_key[12]); // Round 13

	// Round 14
	XOR128(state, state, key->encryption_round_key[13]);
	SL2(state);
	XOR128(state, state, key->encryption_round_key[14]);

	memcpy(ciphertext, state, ARIA_BLOCK_SIZE);
}

void aria192_decrypt_block(aria_key *key, byte_t ciphertext[ARIA_BLOCK_SIZE], byte_t plaintext[ARIA_BLOCK_SIZE])
{
	byte_t state[ARIA_BLOCK_SIZE];

	memcpy(state, ciphertext, ARIA_BLOCK_SIZE);

	FO(state, state, key->decryption_round_key[0]);  // Round 1
	FE(state, state, key->decryption_round_key[1]);  // Round 2
	FO(state, state, key->decryption_round_key[2]);  // Round 3
	FE(state, state, key->decryption_round_key[3]);  // Round 4
	FO(state, state, key->decryption_round_key[4]);  // Round 5
	FE(state, state, key->decryption_round_key[5]);  // Round 6
	FO(state, state, key->decryption_round_key[6]);  // Round 7
	FE(state, state, key->decryption_round_key[7]);  // Round 8
	FO(state, state, key->decryption_round_key[8]);  // Round 9
	FE(state, state, key->decryption_round_key[9]);  // Round 10
	FO(state, state, key->decryption_round_key[10]); // Round 11
	FE(state, state, key->decryption_round_key[11]); // Round 12
	FO(state, state, key->decryption_round_key[12]); // Round 13

	// Round 14
	XOR128(state, state, key->decryption_round_key[13]);
	SL2(state);
	XOR128(state, state, key->decryption_round_key[14]);

	memcpy(plaintext, state, ARIA_BLOCK_SIZE);
}

void aria256_encrypt_block(aria_key *key, byte_t plaintext[ARIA_BLOCK_SIZE], byte_t ciphertext[ARIA_BLOCK_SIZE])
{
	byte_t state[ARIA_BLOCK_SIZE];

	memcpy(state, plaintext, ARIA_BLOCK_SIZE);

	FO(state, state, key->encryption_round_key[0]);  // Round 1
	FE(state, state, key->encryption_round_key[1]);  // Round 2
	FO(state, state, key->encryption_round_key[2]);  // Round 3
	FE(state, state, key->encryption_round_key[3]);  // Round 4
	FO(state, state, key->encryption_round_key[4]);  // Round 5
	FE(state, state, key->encryption_round_key[5]);  // Round 6
	FO(state, state, key->encryption_round_key[6]);  // Round 7
	FE(state, state, key->encryption_round_key[7]);  // Round 8
	FO(state, state, key->encryption_round_key[8]);  // Round 9
	FE(state, state, key->encryption_round_key[9]);  // Round 10
	FO(state, state, key->encryption_round_key[10]); // Round 11
	FE(state, state, key->encryption_round_key[11]); // Round 12
	FO(state, state, key->encryption_round_key[12]); // Round 13
	FE(state, state, key->encryption_round_key[13]); // Round 14
	FO(state, state, key->encryption_round_key[14]); // Round 15

	// Round 16
	XOR128(state, state, key->encryption_round_key[15]);
	SL2(state);
	XOR128(state, state, key->encryption_round_key[16]);

	memcpy(ciphertext, state, ARIA_BLOCK_SIZE);
}

void aria256_decrypt_block(aria_key *key, byte_t ciphertext[ARIA_BLOCK_SIZE], byte_t plaintext[ARIA_BLOCK_SIZE])
{
	byte_t state[ARIA_BLOCK_SIZE];

	memcpy(state, ciphertext, ARIA_BLOCK_SIZE);

	FO(state, state, key->decryption_round_key[0]);  // Round 1
	FE(state, state, key->decryption_round_key[1]);  // Round 2
	FO(state, state, key->decryption_round_key[2]);  // Round 3
	FE(state, state, key->decryption_round_key[3]);  // Round 4
	FO(state, state, key->decryption_round_key[4]);  // Round 5
	FE(state, state, key->decryption_round_key[5]);  // Round 6
	FO(state, state, key->decryption_round_key[6]);  // Round 7
	FE(state, state, key->decryption_round_key[7]);  // Round 8
	FO(state, state, key->decryption_round_key[8]);  // Round 9
	FE(state, state, key->decryption_round_key[9]);  // Round 10
	FO(state, state, key->decryption_round_key[10]); // Round 11
	FE(state, state, key->decryption_round_key[11]); // Round 12
	FO(state, state, key->decryption_round_key[12]); // Round 13
	FE(state, state, key->decryption_round_key[13]); // Round 14
	FO(state, state, key->decryption_round_key[14]); // Round 15

	// Round 16
	XOR128(state, state, key->decryption_round_key[15]);
	SL2(state);
	XOR128(state, state, key->decryption_round_key[16]);

	memcpy(plaintext, state, ARIA_BLOCK_SIZE);
}

static void aria_key_expansion(aria_key *expanded_key, byte_t *actual_key)
{
	uint64_t kl[2], kr[2];
	uint8_t w0[16], w1[16], w2[16], w3[16];
	uint8_t nr = 0;

	uint64_t *k = (uint64_t *)actual_key;
	uint8_t *r = (uint8_t *)kr;

	switch (expanded_key->type)
	{
	case ARIA128:
		kl[0] = k[0];
		kl[1] = k[1];
		kr[0] = 0;
		kr[1] = 0;
		nr = ARIA128_ROUNDS;
		break;
	case ARIA192:
		kl[0] = k[0];
		kl[1] = k[1];
		kr[0] = k[2];
		kr[1] = 0;
		nr = ARIA192_ROUNDS;
		break;
	case ARIA256:
		kl[0] = k[0];
		kl[1] = k[1];
		kr[0] = k[2];
		kr[1] = k[3];
		nr = ARIA256_ROUNDS;
		break;
	}

	// Determine w0, w1, w2, w3

	// W0 = KL
	memcpy(w0, kl, 16);

	// W1 = FO(W0, CK1) ^ KR
	FO(w1, w0, expanded_key->ck1);
	XOR128(w1, w1, r);

	// W2 = FE(W1, CK2) ^ W0
	FE(w2, w1, expanded_key->ck2);
	XOR128(w2, w2, w0);

	// W3 = FO(W2, CK3) ^ W1
	FO(w3, w2, expanded_key->ck3);
	XOR128(w3, w3, w1);

	// Encryption key expansion
	XOR_ROTR19(expanded_key->encryption_round_key[0], w0, w1);
	XOR_ROTR19(expanded_key->encryption_round_key[1], w1, w2);
	XOR_ROTR19(expanded_key->encryption_round_key[2], w2, w3);
	XOR_ROTR19(expanded_key->encryption_round_key[3], w3, w0);

	XOR_ROTR31(expanded_key->encryption_round_key[4], w0, w1);
	XOR_ROTR31(expanded_key->encryption_round_key[5], w1, w2);
	XOR_ROTR31(expanded_key->encryption_round_key[6], w2, w3);
	XOR_ROTR31(expanded_key->encryption_round_key[7], w3, w0);

	XOR_ROTL61(expanded_key->encryption_round_key[8], w0, w1);
	XOR_ROTL61(expanded_key->encryption_round_key[9], w1, w2);
	XOR_ROTL61(expanded_key->encryption_round_key[10], w2, w3);
	XOR_ROTL61(expanded_key->encryption_round_key[11], w3, w0);

	XOR_ROTL31(expanded_key->encryption_round_key[12], w0, w1);

	if (nr > 12)
	{
		// ARIA-192
		XOR_ROTL31(expanded_key->encryption_round_key[13], w1, w2);
		XOR_ROTL31(expanded_key->encryption_round_key[14], w2, w3);

		if (nr > 14)
		{
			// ARIA-256
			XOR_ROTL31(expanded_key->encryption_round_key[15], w3, w0);
			XOR_ROTL19(expanded_key->encryption_round_key[16], w0, w1);
		}
	}

	// Decryption key expansion
	memcpy(expanded_key->decryption_round_key[0], expanded_key->encryption_round_key[nr], sizeof(aria_round_key));

	for (uint8_t i = 1; i < nr; ++i)
	{
		A(expanded_key->decryption_round_key[i], expanded_key->encryption_round_key[nr - i]);
	}

	memcpy(expanded_key->decryption_round_key[nr], expanded_key->encryption_round_key[0], sizeof(aria_round_key));
}

static inline aria_key *aria_key_init_checked(void *ptr, aria_type type, void *key)
{
	aria_key *expanded_key = (aria_key *)ptr;

	memset(expanded_key, 0, sizeof(aria_key));
	expanded_key->type = type;

	switch (type)
	{
	case ARIA128:
		memcpy(expanded_key->ck1, C1, 16);
		memcpy(expanded_key->ck2, C2, 16);
		memcpy(expanded_key->ck3, C3, 16);
		break;
	case ARIA192:
		memcpy(expanded_key->ck1, C2, 16);
		memcpy(expanded_key->ck2, C3, 16);
		memcpy(expanded_key->ck3, C1, 16);
		break;
	case ARIA256:
		memcpy(expanded_key->ck1, C3, 16);
		memcpy(expanded_key->ck2, C1, 16);
		memcpy(expanded_key->ck3, C2, 16);
		break;
	}

	aria_key_expansion(expanded_key, key);

	return expanded_key;
}

aria_key *aria_key_init(void *ptr, size_t size, aria_type type, void *key, size_t key_size)
{
	size_t required_key_size = 0;

	if (size < sizeof(aria_key))
	{
		return NULL;
	}

	switch (type)
	{
	case ARIA128:
		required_key_size = ARIA128_KEY_SIZE;
		break;
	case ARIA192:
		required_key_size = ARIA192_KEY_SIZE;
		break;
	case ARIA256:
		required_key_size = ARIA256_KEY_SIZE;
		break;
	default:
		return NULL;
	}

	if (key_size != required_key_size)
	{
		return NULL;
	}

	return aria_key_init_checked(ptr, type, key);
}

aria_key *aria_key_new(aria_type type, void *key, size_t key_size)
{
	aria_key *expanded_key = NULL;
	size_t required_key_size = 0;

	switch (type)
	{
	case ARIA128:
		required_key_size = ARIA128_KEY_SIZE;
		break;
	case ARIA192:
		required_key_size = ARIA192_KEY_SIZE;
		break;
	case ARIA256:
		required_key_size = ARIA256_KEY_SIZE;
		break;
	default:
		return NULL;
	}

	if (key_size != required_key_size)
	{
		return NULL;
	}

	expanded_key = (aria_key *)malloc(sizeof(aria_key));

	if (expanded_key == NULL)
	{
		return NULL;
	}

	return aria_key_init_checked(expanded_key, type, key);
}

void aria_key_delete(aria_key *key)
{
	// Zero the key for security reasons.
	memset(key, 0, sizeof(aria_key));
	free(key);
}

void aria_encrypt_block(aria_key *key, byte_t plaintext[ARIA_BLOCK_SIZE], byte_t ciphertext[ARIA_BLOCK_SIZE])
{
	switch (key->type)
	{
	case ARIA128:
		return aria128_encrypt_block(key, plaintext, ciphertext);
	case ARIA192:
		return aria192_encrypt_block(key, plaintext, ciphertext);
	case ARIA256:
		return aria256_encrypt_block(key, plaintext, ciphertext);
	}
}
void aria_decrypt_block(aria_key *key, byte_t ciphertext[ARIA_BLOCK_SIZE], byte_t plaintext[ARIA_BLOCK_SIZE])
{
	switch (key->type)
	{
	case ARIA128:
		return aria128_decrypt_block(key, ciphertext, plaintext);
	case ARIA192:
		return aria192_decrypt_block(key, ciphertext, plaintext);
	case ARIA256:
		return aria256_decrypt_block(key, ciphertext, plaintext);
	}
}
