/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_PGP_H
#define SPGP_PGP_H

#include <types.h>
#include <buffer.h>

#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>
#include <round.h>
#include <load.h>

// Armor Flags
#define PGP_ARMOR_NO_CRC 0x1

// Key Constants
#define PGP_KEY_ID_SIZE              8
#define PGP_KEY_MAX_FINGERPRINT_SIZE 32

#endif
