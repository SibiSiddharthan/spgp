/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_CRC24_H
#define SPGP_CRC24_H

#include <pgp.h>

/*
   Name   : "CRC-24"
   Width  : 24
   Poly   : 0x864CFB
   Init   : 0xB704CE
   RefIn  : False
   RefOut : False
   XorOut : 0xFFFFFF
   Check  : 0x21CF02
*/

#define CRC24_INIT  0xB704CE
#define CRC24_POLY  0x864CFB
#define CRC24_FINAL 0xFFFFFF

uint32_t crc24_init(void);
uint32_t crc24_update(uint32_t crc, const void *data, size_t size);
uint32_t crc24_final(uint32_t crc);

#endif
