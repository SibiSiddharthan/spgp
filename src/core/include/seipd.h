/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_SEIPD_H
#define SPGP_SEIPD_H

#include <pgp.h>
#include <packet.h>
#include <stream.h>

#define PGP_MAX_CHUNK_SIZE 16
#define CHUNK_SIZE(size)   ((uint64_t)1 << ((size) + 6))

typedef enum _pgp_seipd_version
{
	PGP_SEIPD_V1 = 1,
	PGP_SEIPD_V2 = 2
} pgp_seipd_version;

typedef enum _pgp_aead_version
{
	PGP_AEAD_V1 = 1
} pgp_aead_version;

typedef struct _pgp_sed_packet
{
	pgp_packet_header header;
	pgp_stream_t *partials;
	byte_t *data;

} pgp_sed_packet;

typedef struct _pgp_seipd_packet
{
	pgp_packet_header header;

	byte_t version; // 1 or 2
	byte_t symmetric_key_algorithm_id;
	byte_t aead_algorithm_id;
	byte_t chunk_size;

	union
	{
		byte_t salt[32];
		byte_t iv[16];
		byte_t mdc[20];
	};

	byte_t tag[16];

	byte_t tag_size;
	byte_t iv_size;
	size_t data_size;

	void *data;
	pgp_stream_t *partials;

} pgp_seipd_packet, pgp_aead_packet;

pgp_error_t pgp_sed_packet_new(pgp_sed_packet **packet);
void pgp_sed_packet_delete(pgp_sed_packet *packet);

pgp_error_t pgp_sed_packet_encrypt(pgp_sed_packet *packet, byte_t symmetric_key_algorithm_id, void *session_key, size_t session_key_size,
								   pgp_stream_t *stream);
pgp_error_t pgp_sed_packet_decrypt(pgp_sed_packet *packet, byte_t symmetric_key_algorithm_id, void *session_key, size_t session_key_size,
								   pgp_stream_t **stream);

pgp_error_t pgp_sed_packet_read(pgp_sed_packet **packet, void *data, size_t size);
size_t pgp_sed_packet_write(pgp_sed_packet *packet, void *ptr, size_t size);
size_t pgp_sed_packet_print(pgp_sed_packet *packet, void *str, size_t size);

pgp_error_t pgp_seipd_packet_new(pgp_seipd_packet **packet, byte_t version, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id,
								 byte_t chunk_size);
void pgp_seipd_packet_delete(pgp_seipd_packet *packet);

pgp_seipd_packet *pgp_seipd_packet_encrypt(pgp_seipd_packet *packet, byte_t salt[32], void *session_key, size_t session_key_size,
										   void *data, size_t data_size);
size_t pgp_seipd_packet_decrypt(pgp_seipd_packet *packet, void *session_key, size_t session_key_size, void *data, size_t data_size);

pgp_error_t pgp_seipd_packet_read(pgp_seipd_packet **packet, void *data, size_t size);
size_t pgp_seipd_packet_write(pgp_seipd_packet *packet, void *ptr, size_t size);
size_t pgp_seipd_packet_print(pgp_seipd_packet *packet, void *str, size_t size);

pgp_error_t pgp_aead_packet_new(pgp_aead_packet **packet, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id, byte_t chunk_size);
void pgp_aead_packet_delete(pgp_aead_packet *packet);

pgp_aead_packet *pgp_aead_packet_encrypt(pgp_aead_packet *packet, byte_t iv[16], byte_t iv_size, void *session_key, size_t session_key_size,
										 void *data, size_t data_size);
size_t pgp_aead_packet_decrypt(pgp_aead_packet *packet, void *session_key, size_t session_key_size, void *data, size_t data_size);

pgp_error_t pgp_aead_packet_read(pgp_aead_packet **packet, void *data, size_t size);
size_t pgp_aead_packet_write(pgp_aead_packet *packet, void *ptr, size_t size);
size_t pgp_aead_packet_print(pgp_aead_packet *packet, void *str, size_t size);

#endif
