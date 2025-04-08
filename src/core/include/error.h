/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_ERROR_H
#define SPGP_ERROR_H

typedef enum _pgp_error_t
{
	// No error
	PGP_NO_ERROR = 0,

	// System errors
	PGP_NO_MEMORY,
	PGP_INSUFFICIENT_DATA,

	// Marker Packet
	PGP_MALFORMED_MARKER_PACKET,

} pgp_error_t;

#endif
