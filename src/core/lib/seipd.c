/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
#include <error.h>
#include <packet.h>
#include <seipd.h>
#include <crypto.h>

#include <stdlib.h>
#include <string.h>

#ifndef SHA1_HASH_SIZE
#	define SHA1_HASH_SIZE 20
#endif

static byte_t check_recursive_encryption_container(pgp_stream_t *stream)
{
	pgp_packet_header *header = NULL;
	pgp_packet_type type = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_SED || type == PGP_SEIPD || type == PGP_AEAD)
		{
			return 1;
		}
	}

	return 0;
}

static size_t pgp_stream_write_internal(pgp_stream_t *stream, void *buffer, size_t size)
{
	size_t pos = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		pos += pgp_packet_write(stream->packets[i], PTR_OFFSET(buffer, pos), size - pos);
	}

	return pos;
}

pgp_error_t pgp_sed_packet_new(pgp_sed_packet **packet)
{
	*packet = malloc(sizeof(pgp_sed_packet));

	if (*packet == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(*packet, 0, sizeof(pgp_sed_packet));

	return PGP_SUCCESS;
}

void pgp_sed_packet_delete(pgp_sed_packet *packet)
{
	free(packet->data);
	free(packet);
}

pgp_error_t pgp_sed_packet_encrypt(pgp_sed_packet *packet, byte_t symmetric_key_algorithm_id, void *session_key, size_t session_key_size,
								   pgp_stream_t *stream)
{
	pgp_error_t status = 0;

	byte_t iv_size = pgp_symmetric_cipher_block_size(symmetric_key_algorithm_id);
	size_t data_size = pgp_packet_stream_octets(stream);
	size_t total_data_size = iv_size + 2 + data_size;

	byte_t partial = 0;

	byte_t zero_iv[16] = {0};
	byte_t message_iv[32] = {0};

	packet->data = malloc(total_data_size);

	if (packet->data == NULL)
	{
		return PGP_NO_MEMORY;
	}

	// N bytes of symmetrically encryrpted data
	partial = total_data_size > ((uint64_t)1 << 32);
	packet->header = pgp_packet_header_encode(PGP_LEGACY_HEADER, PGP_SED, partial, total_data_size);
	packet->data_size = total_data_size;

	// Generate the IV
	status = pgp_rand(message_iv, iv_size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Last 2 octets
	message_iv[iv_size] = message_iv[iv_size - 2];
	message_iv[iv_size + 1] = message_iv[iv_size - 1];

	// Generate the iv
	status = pgp_cfb_encrypt(symmetric_key_algorithm_id, session_key, session_key_size, zero_iv, iv_size, message_iv, iv_size + 2,
							 packet->data, iv_size + 2);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Write the stream
	pgp_stream_write_internal(stream, PTR_OFFSET(packet->data, iv_size + 2), data_size);

	// Encrypt the data
	status = pgp_cfb_encrypt(symmetric_key_algorithm_id, session_key, session_key_size, PTR_OFFSET(packet->data, 2), iv_size,
							 PTR_OFFSET(packet->data, iv_size + 2), data_size, PTR_OFFSET(packet->data, iv_size + 2), data_size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_sed_packet_decrypt(pgp_sed_packet *packet, byte_t symmetric_key_algorithm_id, void *session_key, size_t session_key_size,
								   pgp_stream_t **stream)
{
	pgp_error_t status = 0;

	size_t iv_size = pgp_symmetric_cipher_block_size(symmetric_key_algorithm_id);
	size_t plaintext_size = packet->data_size - (iv_size + 2);

	void *data = NULL;

	byte_t zero_iv[16] = {0};
	byte_t message_iv[32] = {0};

	data = malloc(plaintext_size);

	if (data == NULL)
	{
		return PGP_NO_MEMORY;
	}

	// Decrypt the iv
	status = pgp_cfb_decrypt(symmetric_key_algorithm_id, session_key, session_key_size, zero_iv, iv_size, packet->data, iv_size + 2,
							 message_iv, iv_size + 2);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Check if key is correct
	if (message_iv[iv_size + 1] != message_iv[iv_size - 1] || message_iv[iv_size] != message_iv[iv_size - 2])
	{
		return PGP_CFB_IV_CHECK_MISMATCH;
	}

	// Decrypt the data
	status = pgp_cfb_decrypt(symmetric_key_algorithm_id, session_key, session_key_size, PTR_OFFSET(packet->data, 2), iv_size,
							 PTR_OFFSET(packet->data, iv_size + 2), plaintext_size, data, plaintext_size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	status = pgp_packet_stream_read(stream, data, plaintext_size);

	free(data);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Check for any encrypted packets within
	if (check_recursive_encryption_container(*stream))
	{
		// Don't delete the stream in this case.
		return PGP_RECURSIVE_ENCRYPTION_CONTAINER;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_sed_packet_collate(pgp_sed_packet *packet)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_collate((pgp_data_packet *)packet);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	packet->header = pgp_packet_header_encode(PGP_LEGACY_HEADER, PGP_SED, packet->data_size > ((uint64_t)1 << 32), packet->data_size);

	return PGP_SUCCESS;
}

pgp_error_t pgp_sed_packet_split(pgp_sed_packet *packet, byte_t split)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_split((pgp_data_packet *)packet, split);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	packet->header = pgp_packet_header_encode(PGP_HEADER, PGP_SED, 1, packet->data_size);

	return PGP_SUCCESS;
}

pgp_error_t pgp_sed_packet_read_with_header(pgp_sed_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_sed_packet *sed = NULL;

	sed = malloc(sizeof(pgp_sed_packet));

	if (packet == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(sed, 0, sizeof(pgp_sed_packet));

	sed->data = malloc(header->body_size);

	if (sed->data == NULL)
	{
		pgp_sed_packet_delete(sed);
		return PGP_NO_MEMORY;
	}

	// Copy the header
	sed->header = *header;

	// Copy the packet data.
	memcpy(sed->data, PTR_OFFSET(data, header->header_size), header->body_size);
	sed->data_size = header->body_size;

	*packet = sed;

	return PGP_SUCCESS;
}

pgp_error_t pgp_sed_packet_read(pgp_sed_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_SED)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_sed_packet_read_with_header(packet, &header, data);
}

size_t pgp_sed_packet_write(pgp_sed_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	size_t required_size = 0;

	required_size = PGP_PACKET_OCTETS(packet->header);

	if (packet->partials != NULL)
	{
		required_size += pgp_packet_stream_octets(packet->partials);
	}

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	if (packet->partials != NULL)
	{
		for (uint32_t i = 0; i < packet->partials->count; ++i)
		{
			pos += pgp_partial_packet_write(packet->partials->packets[i], out + pos, size - pos);
		}
	}

	return pos;
}

static void pgp_seipd_packet_encode_header(pgp_seipd_packet *packet, byte_t partial)
{
	uint32_t body_size = 0;

	if (packet->version == PGP_SEIPD_V2)
	{
		// Always create V1 packets with new format headers
		// A 1-octet version number with value 2.
		// A 1-octet symmetric key algorithm.
		// A 1-octet AEAD algorithm.
		// A 1-octet chunk size.
		// A 32-octets of salt.
		// Symmetrically encryrpted data
		// Authentication tag

		body_size = 1 + 1 + 1 + 1 + 32 + packet->data_size + packet->tag_size;
		packet->header = pgp_packet_header_encode(PGP_HEADER, PGP_SEIPD, partial, body_size);
	}

	if (packet->version == PGP_SEIPD_V1)
	{
		// Always create V1 packets with legacy format headers
		// A 1-octet version number with value 1.
		// N octets of symmetrically encryrpted data

		body_size = 1 + packet->data_size;
		packet->header = pgp_packet_header_encode(PGP_HEADER, PGP_SEIPD, partial, body_size);
	}
}

pgp_error_t pgp_seipd_packet_new(pgp_seipd_packet **packet, byte_t version, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id,
								 byte_t chunk_size)
{
	pgp_seipd_packet *seipd = NULL;

	if (version != PGP_SEIPD_V2 && version != PGP_SEIPD_V1)
	{
		return PGP_UNKNOWN_SEIPD_PACKET_VERSION;
	}

	if (pgp_symmetric_cipher_algorithm_validate(symmetric_key_algorithm_id) == 0)
	{
		return PGP_UNKNOWN_CIPHER_ALGORITHM;
	}

	if (version == PGP_SEIPD_V2)
	{
		if (chunk_size > PGP_MAX_CHUNK_SIZE)
		{
			return PGP_INVALID_CHUNK_SIZE;
		}

		if (pgp_aead_algorithm_validate(aead_algorithm_id) == 0)
		{
			return PGP_UNKNOWN_AEAD_ALGORITHM;
		}
	}

	seipd = malloc(sizeof(pgp_seipd_packet));

	if (packet == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(seipd, 0, sizeof(pgp_seipd_packet));

	if (version == PGP_SEIPD_V2)
	{
		seipd->version = PGP_SEIPD_V2;
		seipd->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
		seipd->aead_algorithm_id = aead_algorithm_id;
		seipd->chunk_size = chunk_size;
	}
	else
	{
		seipd->version = PGP_SEIPD_V1;
		seipd->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
	}

	pgp_seipd_packet_encode_header(seipd, 0);

	*packet = seipd;

	return PGP_SUCCESS;
}

void pgp_seipd_packet_delete(pgp_seipd_packet *packet)
{
	free(packet->data);
	free(packet);
}

static pgp_error_t pgp_seipd_packet_v1_encrypt(pgp_seipd_packet *packet, void *session_key, size_t session_key_size, pgp_stream_t *stream)
{
	pgp_error_t status = 0;
	byte_t block_size = pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id);

	byte_t zero_iv[16] = {0};
	byte_t prefix[18] = {0};
	byte_t trailer[2] = {0xD3, 0x14};

	size_t data_size = pgp_packet_stream_octets(stream);
	uint64_t pos = 0;

	packet->data_size = block_size + 2 + data_size + 2 + SHA1_HASH_SIZE;
	packet->data = malloc(packet->data_size);

	if (packet->data == NULL)
	{
		return PGP_NO_MEMORY;
	}

	// Generate random prefix of block size
	status = pgp_rand(prefix, block_size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Copy last 2 octets
	prefix[block_size] = prefix[block_size - 2];
	prefix[block_size + 1] = prefix[block_size - 1];

	// Copy the prefix
	memcpy(PTR_OFFSET(packet->data, pos), prefix, block_size + 2);
	pos += block_size + 2;

	// Write the stream
	pgp_stream_write_internal(stream, PTR_OFFSET(packet->data, pos), data_size);
	pos += data_size;

	// Copy the trailer
	memcpy(PTR_OFFSET(packet->data, pos), trailer, 2);
	pos += 2;

	// Hash prefix | plaintext | trailer
	status = pgp_hash(PGP_SHA1, packet->data, pos, PTR_OFFSET(packet->data, pos), SHA1_HASH_SIZE);
	pos += SHA1_HASH_SIZE;

	if (status != PGP_SUCCESS)
	{
		free(packet->data);
		return status;
	}

	// Encrypt the plaintext and mdc
	status = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, session_key, session_key_size, zero_iv, block_size, packet->data,
							 packet->data_size, packet->data, packet->data_size);

	if (status != PGP_SUCCESS)
	{
		free(packet->data);
		return status;
	}

	// Update header
	pgp_seipd_packet_encode_header(packet, 0);

	return PGP_SUCCESS;
}

static pgp_error_t pgp_seipd_packet_v1_decrypt(pgp_seipd_packet *packet, void *session_key, size_t session_key_size, pgp_stream_t **stream)
{
	pgp_error_t status = 0;
	byte_t block_size = pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id);
	size_t plaintext_size = packet->data_size - (block_size + 4 + SHA1_HASH_SIZE);

	byte_t prefix[18] = {0};
	void *temp = NULL;

	byte_t zero_iv[16] = {0};
	byte_t mdc[SHA1_HASH_SIZE] = {0};

	temp = malloc(packet->data_size);

	if (temp == NULL)
	{
		return PGP_NO_MEMORY;
	}

	// Decrypt everything
	status = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, session_key, session_key_size, zero_iv, block_size, packet->data,
							 packet->data_size, temp, packet->data_size);

	if (status != PGP_SUCCESS)
	{
		free(temp);
		return status;
	}

	// Copy the prefix
	memcpy(prefix, temp, block_size + 2);

	// Check whether the session key is correct
	if (prefix[block_size] != prefix[block_size - 2] || prefix[block_size + 1] != prefix[block_size - 1])
	{
		free(temp);
		return PGP_CFB_IV_CHECK_MISMATCH;
	}

	// Calculate the hash
	status = pgp_hash(PGP_SHA1, temp, packet->data_size - SHA1_HASH_SIZE, mdc, SHA1_HASH_SIZE);

	if (status != PGP_SUCCESS)
	{
		free(temp);
		return status;
	}

	// Compare the hash
	if (memcmp(mdc, PTR_OFFSET(temp, packet->data_size - SHA1_HASH_SIZE), SHA1_HASH_SIZE) != 0)
	{
		free(temp);
		return PGP_MDC_TAG_MISMATCH;
	}

	// Read the decrypted text
	status = pgp_packet_stream_read(stream, PTR_OFFSET(temp, block_size + 2), plaintext_size);
	free(temp);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Check for any encrypted packets within
	if (check_recursive_encryption_container(*stream))
	{
		// Don't delete the stream in this case.
		return PGP_RECURSIVE_ENCRYPTION_CONTAINER;
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_seipd_packet_v2_encrypt(pgp_seipd_packet *packet, byte_t salt[32], void *session_key, size_t session_key_size,
											   pgp_stream_t *stream)
{
	pgp_error_t status = 0;

	uint32_t chunk_size = PGP_CHUNK_SIZE(packet->chunk_size);
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	byte_t iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);

	size_t in_pos = 0;
	size_t out_pos = 0;
	size_t count = 0;
	size_t count_be = 0;
	size_t data_size = pgp_packet_stream_octets(stream);

	byte_t derived_key[48] = {0};
	byte_t iv[16] = {0};
	byte_t info[5] = {0};

	void *data = NULL;
	byte_t *in = NULL;
	byte_t *out = NULL;

	info[0] = packet->header.tag;
	info[1] = packet->version;
	info[2] = packet->symmetric_key_algorithm_id;
	info[3] = packet->aead_algorithm_id;
	info[4] = packet->chunk_size;

	// Copy the salt
	memcpy(packet->salt, salt, 32);

	// Derive the message key
	pgp_hkdf(PGP_SHA2_256, session_key, session_key_size, salt, 32, info, 5, derived_key, key_size + iv_size - 8);

	// Copy part of the it as IV
	memcpy(iv, PTR_OFFSET(derived_key, key_size), iv_size - 8);

	// Encrypt the data paritioned by chunk size
	packet->data_size = (data_size / chunk_size) * (chunk_size + PGP_AEAD_TAG_SIZE) + ((data_size % chunk_size) + PGP_AEAD_TAG_SIZE);
	packet->data = malloc(packet->data_size);

	data = malloc(data_size);

	if (packet->data == NULL || data == NULL)
	{
		free(packet->data);
		free(data);

		return PGP_NO_MEMORY;
	}

	pgp_stream_write_internal(stream, data, data_size);

	in = data;
	out = packet->data;

	while (in_pos < data_size)
	{
		uint32_t in_size = MIN(chunk_size, data_size - in_pos);
		count_be = BSWAP_64(count);

		memcpy(PTR_OFFSET(iv, iv_size - 8), &count_be, 8);

		// Encrypt the data
		status = pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size, iv, iv_size, info,
								  5, in + in_pos, in_size, out + out_pos, in_size + PGP_AEAD_TAG_SIZE);

		if (status != PGP_SUCCESS)
		{
			free(packet->data);
			free(data);
			return status;
		}

		in_pos += in_size;
		out_pos += in_size + PGP_AEAD_TAG_SIZE;
		++count;
	}

	free(data);

	// Final authentication tag
	byte_t aad[16] = {0};
	size_t octets_be = BSWAP_64(data_size);

	packet->tag_size = PGP_AEAD_TAG_SIZE;

	// Same as info
	aad[0] = info[0];
	aad[1] = info[1];
	aad[2] = info[2];
	aad[3] = info[3];
	aad[4] = info[4];

	// Store number of plaintext octets as 8 byte big endian
	memcpy(PTR_OFFSET(aad, 5), &octets_be, 8);

	// Last chunk
	count_be = BSWAP_64(count);
	memcpy(PTR_OFFSET(iv, iv_size - 8), &count_be, 8);

	status = pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size, iv, iv_size, aad, 13,
							  NULL, 0, packet->tag, packet->tag_size);

	if (status != PGP_SUCCESS)
	{
		free(packet->data);
		return status;
	}

	// Update header
	pgp_seipd_packet_encode_header(packet, 0);

	return PGP_SUCCESS;
}

static pgp_error_t pgp_seipd_packet_v2_decrypt(pgp_seipd_packet *packet, void *session_key, size_t session_key_size, pgp_stream_t **stream)
{
	pgp_error_t status = 0;

	uint32_t chunk_size = PGP_CHUNK_SIZE(packet->chunk_size);
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	byte_t iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);

	size_t in_pos = 0;
	size_t out_pos = 0;
	size_t count = 0;
	size_t count_be = 0;

	byte_t derived_key[48] = {0};
	byte_t iv[16] = {0};
	byte_t info[5] = {0};

	void *temp = NULL;
	byte_t *in = NULL;
	byte_t *out = NULL;

	info[0] = packet->header.tag;
	info[1] = packet->version;
	info[2] = packet->symmetric_key_algorithm_id;
	info[3] = packet->aead_algorithm_id;
	info[4] = packet->chunk_size;

	// Derive the message key
	pgp_hkdf(PGP_SHA2_256, session_key, session_key_size, packet->salt, 32, info, 5, derived_key, key_size + iv_size - 8);

	// Copy part of the it as IV
	memcpy(iv, PTR_OFFSET(derived_key, key_size), iv_size - 8);

	temp = malloc(packet->data_size);

	if (temp == NULL)
	{
		return PGP_NO_MEMORY;
	}

	in = packet->data;
	out = temp;

	// Decrypt the data paritioned by chunk size + tag size
	while (in_pos < packet->data_size)
	{
		uint32_t in_size = MIN(chunk_size + packet->tag_size, packet->data_size - in_pos);
		count_be = BSWAP_64(count);

		memcpy(PTR_OFFSET(iv, iv_size - 8), &count_be, 8);

		// Decrypt the data
		status = pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size, iv, iv_size, info,
								  5, in + in_pos, in_size, out + out_pos, in_size - PGP_AEAD_TAG_SIZE);

		if (status != PGP_SUCCESS)
		{
			free(temp);
			return status;
		}

		in_pos += in_size;
		out_pos += in_size - PGP_AEAD_TAG_SIZE;
		++count;
	}

	// Final authentication tag
	byte_t aad[16] = {0};
	size_t octets_be = BSWAP_64(out_pos);

	packet->tag_size = PGP_AEAD_TAG_SIZE;

	// Same as info
	aad[0] = info[0];
	aad[1] = info[1];
	aad[2] = info[2];
	aad[3] = info[3];
	aad[4] = info[4];

	// Store number of chunks as 8 byte big endian
	memcpy(PTR_OFFSET(aad, 5), &octets_be, 8);

	// Last chunk
	count_be = BSWAP_64(count);
	memcpy(PTR_OFFSET(iv, iv_size - 8), &count_be, 8);

	status = pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size, iv, iv_size, aad, 13,
							  packet->tag, PGP_AEAD_TAG_SIZE, NULL, 0);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Read the decrypted text
	status = pgp_packet_stream_read(stream, temp, out_pos);
	free(temp);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Check for any encrypted packets within
	if (check_recursive_encryption_container(*stream))
	{
		// Don't delete the stream in this case.
		return PGP_RECURSIVE_ENCRYPTION_CONTAINER;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_seipd_packet_encrypt(pgp_seipd_packet *packet, byte_t salt[32], void *session_key, size_t session_key_size,
									 pgp_stream_t *stream)
{

	switch (packet->version)
	{
	case PGP_SEIPD_V1:
		return pgp_seipd_packet_v1_encrypt(packet, session_key, session_key_size, stream);
	case PGP_SEIPD_V2:
		return pgp_seipd_packet_v2_encrypt(packet, salt, session_key, session_key_size, stream);
	}

	return PGP_UNKNOWN_SEIPD_PACKET_VERSION;
}

pgp_error_t pgp_seipd_packet_decrypt(pgp_seipd_packet *packet, void *session_key, size_t session_key_size, pgp_stream_t **stream)
{

	switch (packet->version)
	{
	case PGP_SEIPD_V1:
		return pgp_seipd_packet_v1_decrypt(packet, session_key, session_key_size, stream);
	case PGP_SEIPD_V2:
		return pgp_seipd_packet_v2_decrypt(packet, session_key, session_key_size, stream);
	}

	return PGP_UNKNOWN_SEIPD_PACKET_VERSION;
}

pgp_error_t pgp_seipd_packet_collate(pgp_seipd_packet *packet)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_collate((pgp_data_packet *)packet);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	pgp_seipd_packet_encode_header(packet, 0);

	return PGP_SUCCESS;
}

pgp_error_t pgp_seipd_packet_split(pgp_seipd_packet *packet, byte_t split)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_split((pgp_data_packet *)packet, split);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	pgp_seipd_packet_encode_header(packet, 1);

	return PGP_SUCCESS;
}

static pgp_error_t pgp_seipd_packet_read_body(pgp_seipd_packet *packet, buffer_t *buffer)
{
	// 1 octet version
	CHECK_READ(read8(buffer, &packet->version), PGP_MALFORMED_SEIPD_PACKET);

	if (packet->version == PGP_SEIPD_V2)
	{
		// 1 octet symmetric key algorithm
		CHECK_READ(read8(buffer, &packet->symmetric_key_algorithm_id), PGP_MALFORMED_SEIPD_PACKET);

		// 1 octet AEAD algorithm
		CHECK_READ(read8(buffer, &packet->aead_algorithm_id), PGP_MALFORMED_SEIPD_PACKET);

		// 1 octet chunk size
		CHECK_READ(read8(buffer, &packet->chunk_size), PGP_MALFORMED_SEIPD_PACKET);

		// 32-octets of salt
		CHECK_READ(readn(buffer, packet->salt, 32), PGP_MALFORMED_SEIPD_PACKET);

		// Data
		packet->data_size = buffer->size - buffer->pos - PGP_AEAD_TAG_SIZE;
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			return PGP_NO_MEMORY;
		}

		CHECK_READ(readn(buffer, packet->data, packet->data_size), PGP_MALFORMED_SEIPD_PACKET);

		// Tag
		packet->tag_size = PGP_AEAD_TAG_SIZE;
		CHECK_READ(readn(buffer, packet->tag, packet->tag_size), PGP_MALFORMED_SEIPD_PACKET);
	}
	else if (packet->version == PGP_SEIPD_V1)
	{
		// Data
		packet->data_size = packet->header.body_size - 1;
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			return PGP_NO_MEMORY;
		}

		CHECK_READ(readn(buffer, packet->data, packet->data_size), PGP_MALFORMED_SEIPD_PACKET);
	}
	else
	{
		// Unknown version
		return PGP_UNKNOWN_SEIPD_PACKET_VERSION;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_seipd_packet_read_with_header(pgp_seipd_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_seipd_packet *seipd = NULL;

	seipd = malloc(sizeof(pgp_seipd_packet));

	if (seipd == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(seipd, 0, sizeof(pgp_aead_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	seipd->header = *header;

	// Read the body
	error = pgp_seipd_packet_read_body(seipd, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_seipd_packet_delete(seipd);
		return error;
	}

	*packet = seipd;

	return error;
}

pgp_error_t pgp_seipd_packet_read(pgp_seipd_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_SEIPD)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_seipd_packet_read_with_header(packet, &header, data);
}

static size_t pgp_seipd_packet_v1_write(pgp_seipd_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// Data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	// Write the partials
	if (packet->partials != NULL)
	{
		for (uint32_t i = 0; i < packet->partials->count; ++i)
		{
			pos += pgp_partial_packet_write(packet->partials->packets[i], out + pos, size - pos);
		}
	}

	return pos;
}

static size_t pgp_seipd_packet_v2_write(pgp_seipd_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 1 octet symmetric key algorithm
	LOAD_8(out + pos, &packet->symmetric_key_algorithm_id);
	pos += 1;

	// 1 octet AEAD algorithm
	LOAD_8(out + pos, &packet->aead_algorithm_id);
	pos += 1;

	// 1 octet chunk size
	LOAD_8(out + pos, &packet->chunk_size);
	pos += 1;

	// 32-octets of salt
	memcpy(out + pos, packet->salt, 32);
	pos += 32;

	// Data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	if (packet->partials != NULL)
	{
		// The last partial packet will contain the tag
		for (uint32_t i = 0; i < packet->partials->count; ++i)
		{
			pos += pgp_partial_packet_write(packet->partials->packets[i], out + pos, size - pos);
		}
	}
	else
	{
		// Tag
		memcpy(out + pos, packet->tag, packet->tag_size);
		pos += packet->tag_size;
	}

	return pos;
}

size_t pgp_seipd_packet_write(pgp_seipd_packet *packet, void *ptr, size_t size)
{
	size_t required_size = 0;

	required_size = PGP_PACKET_OCTETS(packet->header);

	if (packet->partials != NULL)
	{
		required_size += pgp_packet_stream_octets(packet->partials);
	}

	if (size < required_size)
	{
		return 0;
	}

	switch (packet->version)
	{
	case PGP_SEIPD_V1:
		return pgp_seipd_packet_v1_write(packet, ptr, size);
	case PGP_SEIPD_V2:
		return pgp_seipd_packet_v2_write(packet, ptr, size);
	default:
		return 0;
	}
}

static void pgp_aead_packet_encode_header(pgp_aead_packet *packet, byte_t partial)
{
	uint32_t body_size = 0;

	// A 1-octet version number with value 1.
	// A 1-octet symmetric key algorithm.
	// A 1-octet AEAD algorithm.
	// A 1-octet chunk size.
	// A 12/15/16-octets of IV.
	// Symmetrically encryrpted data
	// Authentication tag

	body_size = 1 + 1 + 1 + 1 + packet->iv_size + packet->data_size + packet->tag_size;
	packet->header = pgp_packet_header_encode(PGP_HEADER, PGP_AEAD, partial, body_size);
}

pgp_error_t pgp_aead_packet_new(pgp_aead_packet **packet, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id, byte_t chunk_size)
{
	pgp_aead_packet *aead = NULL;

	if (pgp_symmetric_cipher_algorithm_validate(symmetric_key_algorithm_id) == 0)
	{
		return PGP_UNKNOWN_CIPHER_ALGORITHM;
	}

	if (pgp_aead_algorithm_validate(aead_algorithm_id) == 0)
	{
		return PGP_UNKNOWN_AEAD_ALGORITHM;
	}

	if (chunk_size > PGP_MAX_CHUNK_SIZE)
	{
		return PGP_INVALID_CHUNK_SIZE;
	}

	aead = malloc(sizeof(pgp_aead_packet));

	if (aead == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(aead, 0, sizeof(pgp_aead_packet));

	aead->version = PGP_AEAD_V1;
	aead->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
	aead->aead_algorithm_id = aead_algorithm_id;
	aead->chunk_size = chunk_size;

	pgp_aead_packet_encode_header(aead, 0);

	*packet = aead;

	return PGP_SUCCESS;
}

void pgp_aead_packet_delete(pgp_aead_packet *packet)
{
	free(packet->data);
	free(packet);
}

pgp_error_t pgp_aead_packet_encrypt(pgp_aead_packet *packet, byte_t iv[16], byte_t iv_size, void *session_key, size_t session_key_size,
									pgp_stream_t *stream)
{
	pgp_error_t status = 0;
	uint32_t chunk_size = PGP_CHUNK_SIZE(packet->chunk_size);

	size_t in_pos = 0;
	size_t out_pos = 0;
	size_t count = 0;
	size_t data_size = pgp_packet_stream_octets(stream);

	byte_t aad[32] = {0};

	void *data = NULL;
	byte_t *in = NULL;
	byte_t *out = NULL;

	aad[0] = packet->header.tag;
	aad[1] = packet->version;
	aad[2] = packet->symmetric_key_algorithm_id;
	aad[3] = packet->aead_algorithm_id;
	aad[4] = packet->chunk_size;

	if (iv_size != pgp_aead_iv_size(packet->aead_algorithm_id))
	{
		return PGP_INVALID_AEAD_IV_SIZE;
	}

	// Copy the IV
	memcpy(packet->iv, iv, iv_size);
	packet->iv_size = iv_size;

	// Encrypt the data paritioned by chunk size
	packet->data_size = (data_size / chunk_size) * (chunk_size + PGP_AEAD_TAG_SIZE) + ((data_size % chunk_size) + PGP_AEAD_TAG_SIZE);
	packet->data = malloc(packet->data_size);

	data = malloc(data_size);

	if (packet->data == NULL || data == NULL)
	{
		free(packet->data);
		free(data);

		return PGP_NO_MEMORY;
	}

	pgp_stream_write_internal(stream, data, data_size);

	in = data;
	out = packet->data;

	while (in_pos < data_size)
	{
		uint32_t in_size = MIN(chunk_size, data_size - in_pos);
		size_t count_be = BSWAP_64(count);

		memcpy(PTR_OFFSET(aad, 5), &count_be, 8);

		// Encrypt the data
		status = pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, session_key, session_key_size, iv, iv_size,
								  aad, 13, in + in_pos, in_size, out + out_pos, in_size + PGP_AEAD_TAG_SIZE);

		if (status != PGP_SUCCESS)
		{
			free(data);
			return status;
		}

		in_pos += in_size;
		out_pos += in_size + PGP_AEAD_TAG_SIZE;
		++count;
	}

	free(data);

	// Final authentication tag
	size_t count_be = BSWAP_64(count);
	size_t octets_be = BSWAP_64(data_size);

	packet->tag_size = PGP_AEAD_TAG_SIZE;

	memcpy(PTR_OFFSET(aad, 5), &count_be, 8);
	memcpy(PTR_OFFSET(aad, 13), &octets_be, 8);

	status = pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, session_key, session_key_size, iv, iv_size,
							  aad, 21, NULL, 0, packet->tag, PGP_AEAD_TAG_SIZE);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	pgp_aead_packet_encode_header(packet, 0);

	return PGP_SUCCESS;
}

pgp_error_t pgp_aead_packet_decrypt(pgp_aead_packet *packet, void *session_key, size_t session_key_size, pgp_stream_t **stream)
{
	pgp_error_t status = 0;

	uint32_t chunk_size = PGP_CHUNK_SIZE(packet->chunk_size);
	byte_t iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);

	size_t in_pos = 0;
	size_t out_pos = 0;
	size_t count = 0;

	byte_t aad[32] = {0};

	void *temp = NULL;
	byte_t *in = NULL;
	byte_t *out = NULL;

	aad[0] = packet->header.tag;
	aad[1] = packet->version;
	aad[2] = packet->symmetric_key_algorithm_id;
	aad[3] = packet->aead_algorithm_id;
	aad[4] = packet->chunk_size;

	temp = malloc(packet->data_size);

	if (temp == NULL)
	{
		return PGP_NO_MEMORY;
	}

	in = packet->data;
	out = temp;

	// Decrypt the data paritioned by chunk size + tag size
	while (in_pos < packet->data_size)
	{
		uint32_t in_size = MIN(chunk_size + packet->tag_size, packet->data_size - in_pos);
		size_t count_be = BSWAP_64(count);

		memcpy(PTR_OFFSET(aad, 5), &count_be, 8);

		// Decrypt the data
		status = pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, session_key, session_key_size, packet->iv,
								  iv_size, aad, 13, in + in_pos, in_size, out + out_pos, in_size - PGP_AEAD_TAG_SIZE);

		if (status != PGP_SUCCESS)
		{
			free(temp);
			return PGP_AEAD_TAG_MISMATCH;
		}

		in_pos += in_size;
		out_pos += in_size - PGP_AEAD_TAG_SIZE;
		++count;
	}

	// Final authentication tag
	size_t count_be = BSWAP_64(count);
	size_t octets_be = BSWAP_64(out_pos);

	memcpy(PTR_OFFSET(aad, 5), &count_be, 8);
	memcpy(PTR_OFFSET(aad, 13), &octets_be, 8);

	status = pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, session_key, session_key_size, packet->iv,
							  iv_size, aad, 21, packet->tag, PGP_AEAD_TAG_SIZE, NULL, 0);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Read the decrypted text
	status = pgp_packet_stream_read(stream, temp, out_pos);
	free(temp);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Check for any encrypted packets within
	if (check_recursive_encryption_container(*stream))
	{
		// Don't delete the stream in this case.
		return PGP_RECURSIVE_ENCRYPTION_CONTAINER;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_aead_packet_collate(pgp_aead_packet *packet)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_collate((pgp_data_packet *)packet);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	pgp_aead_packet_encode_header(packet, 0);

	return PGP_SUCCESS;
}

pgp_error_t pgp_aead_packet_split(pgp_aead_packet *packet, byte_t split)
{
	pgp_error_t status = 0;

	status = pgp_data_packet_split((pgp_data_packet *)packet, split);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Update the header
	pgp_aead_packet_encode_header(packet, 1);

	return PGP_SUCCESS;
}

pgp_error_t pgp_aead_packet_read_body(pgp_aead_packet *packet, buffer_t *buffer)
{
	// 1 octet version
	CHECK_READ(read8(buffer, &packet->version), PGP_MALFORMED_AEAD_PACKET);

	if (packet->version == PGP_AEAD_V1)
	{
		// 1 octet symmetric key algorithm
		CHECK_READ(read8(buffer, &packet->symmetric_key_algorithm_id), PGP_MALFORMED_AEAD_PACKET);

		// 1 octet AEAD algorithm
		CHECK_READ(read8(buffer, &packet->aead_algorithm_id), PGP_MALFORMED_AEAD_PACKET);

		// 1 octet chunk size
		CHECK_READ(read8(buffer, &packet->chunk_size), PGP_MALFORMED_AEAD_PACKET);

		// IV
		packet->iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);
		CHECK_READ(readn(buffer, packet->iv, packet->iv_size), PGP_MALFORMED_AEAD_PACKET);

		// Data
		packet->data_size = buffer->size - buffer->pos - PGP_AEAD_TAG_SIZE;
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			return PGP_NO_MEMORY;
		}

		CHECK_READ(readn(buffer, packet->data, packet->data_size), PGP_MALFORMED_AEAD_PACKET);

		// Tag
		packet->tag_size = PGP_AEAD_TAG_SIZE;
		CHECK_READ(readn(buffer, packet->tag, packet->tag_size), PGP_MALFORMED_AEAD_PACKET);
	}
	else
	{
		// Unknown version
		return PGP_UNKNOWN_AEAD_PACKET_VERSION;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_aead_packet_read_with_header(pgp_aead_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_aead_packet *aead = NULL;

	aead = malloc(sizeof(pgp_aead_packet));

	if (aead == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(aead, 0, sizeof(pgp_aead_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	aead->header = *header;

	// Read the body
	error = pgp_aead_packet_read_body(aead, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_aead_packet_delete(aead);
		return error;
	}

	*packet = aead;

	return error;
}

pgp_error_t pgp_aead_packet_read(pgp_aead_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_AEAD)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_aead_packet_read_with_header(packet, &header, data);
}

size_t pgp_aead_packet_write(pgp_aead_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	size_t required_size = 0;

	required_size = PGP_PACKET_OCTETS(packet->header);

	if (packet->partials != NULL)
	{
		required_size += pgp_packet_stream_octets(packet->partials);
	}

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 1 octet symmetric key algorithm
	LOAD_8(out + pos, &packet->symmetric_key_algorithm_id);
	pos += 1;

	// 1 octet AEAD algorithm
	LOAD_8(out + pos, &packet->aead_algorithm_id);
	pos += 1;

	// 1 octet chunk size
	LOAD_8(out + pos, &packet->chunk_size);
	pos += 1;

	// IV
	memcpy(out + pos, packet->iv, packet->iv_size);
	pos += packet->iv_size;

	// Data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	if (packet->partials != NULL)
	{
		// The last partial packet will contain the tag
		for (uint32_t i = 0; i < packet->partials->count; ++i)
		{
			pos += pgp_partial_packet_write(packet->partials->packets[i], out + pos, size - pos);
		}
	}
	else
	{
		// Tag
		memcpy(out + pos, packet->tag, packet->tag_size);
		pos += packet->tag_size;
	}

	return pos;
}
