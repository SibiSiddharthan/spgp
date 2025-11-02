/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_ARMOR_H
#define SPGP_ARMOR_H

#include <pgp/pgp.h>
#include <armor.h>

#define PGP_ARMOR_BEGIN_MESSAGE "BEGIN PGP MESSAGE"
#define PGP_ARMOR_END_MESSAGE   "END PGP MESSAGE"

#define PGP_ARMOR_BEGIN_PUBLIC_KEY "BEGIN PGP PUBLIC KEY BLOCK"
#define PGP_ARMOR_END_PUBLIC_KEY   "END PGP PUBLIC KEY BLOCK"

#define PGP_ARMOR_BEGIN_PRIVATE_KEY "BEGIN PGP PRIVATE KEY BLOCK"
#define PGP_ARMOR_END_PRIVATE_KEY   "END PGP PRIVATE KEY BLOCK"

#define PGP_ARMOR_BEGIN_SIGNATURE "BEGIN PGP SIGNATURE"
#define PGP_ARMOR_END_SIGNATURE   "END PGP SIGNATURE"

#define PGP_ARMOR_CLEARTEXT "-----BEGIN PGP SIGNED MESSAGE-----"

#define PGP_ARMOR_HEADER_VERSION    "Version"
#define PGP_ARMOR_HEADER_HASH       "Hash"
#define PGP_ARMOR_HEADER_CHARSET    "Charset"
#define PGP_ARMOR_HEADER_COMMENT    "Comment"
#define PGP_ARMOR_HEADER_MESSAGE_ID "MessageID"

#endif
