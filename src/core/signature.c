/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <signature.h>

uint32_t get_signature_size(pgp_public_key_algorithms algorithm);
uint32_t get_header_size(pgp_packet_header_type type, size_t size);
uint32_t pgp_packet_header_write(pgp_packet_header *header, void *ptr);
uint32_t pgp_signature_data_write(pgp_public_key_algorithms algorithm, void *data, void *ptr);

uint32_t pgp_signature_packet_v3_write(pgp_signature_packet *packet, void *ptr, uint32_t size)
{
	byte_t *out = ptr;
	uint32_t required_size = 0;
	uint32_t pos = 0;

	// A 1-octet version number with value 3.
	// A 1-octet length of the following hashed material; it be 5:
	// A 1-octet Signature Type ID.
	// A 4-octet creation time.
	// An 8-octet Key ID of the signer.
	// A 1-octet public key algorithm.
	// A 1-octet hash algorithm.
	// A 2-octet field holding left 16 bits of the signed hash value.
	// One or more MPIs comprising the signature

	required_size = 1 + 1 + 1 + 4 + 8 + 1 + 1 + 2 + get_signature_size(packet->public_key_algorithm_id);
	required_size += get_header_size(PGP_LEGACY_HEADER, required_size);

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 1 octet hashed length
	LOAD_8(out + pos, &packet->hashed_size);
	pos += 1;

	// 1 octet signature type
	LOAD_8(out + pos, &packet->type);
	pos += 1;

	// 4 octet timestamp
	uint32_t timestamp = BSWAP_32(packet->timestamp);
	LOAD_32(out + pos, &timestamp);
	pos += 4;

	// 8 octet key-id
	LOAD_64(out + pos, &packet->key_id);
	pos += 8;

	// 1 octet public-key algorithm
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	// 1 octet hash algorithm
	LOAD_8(out + pos, &packet->hash_algorithm_id);
	pos += 1;

	// 2 octets of the left 16 bits of signed hash value
	LOAD_16(out + pos, &packet->quick_hash);
	pos += 2;

	// signature stuff
	pos += pgp_signature_data_write(packet->public_key_algorithm_id, packet->signature, out + pos);

	return pos;
}
