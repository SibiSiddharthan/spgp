/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <seipd.h>
#include <crypto.h>

#include <stdlib.h>
#include <string.h>

#include <hkdf.h>
#include <sha.h>

pgp_sed_packet *pgp_sed_packet_new()
{
	return malloc(sizeof(pgp_sed_packet));
}

void pgp_sed_packet_delete(pgp_sed_packet *packet)
{
	free(packet->data);
	free(packet);
}

pgp_sed_packet *pgp_sed_packet_encrypt(pgp_sed_packet *packet, byte_t symmetric_key_algorithm_id, void *session_key,
									   size_t session_key_size, void *data, size_t data_size)
{
	byte_t iv_size = pgp_symmetric_cipher_block_size(symmetric_key_algorithm_id);
	size_t total_data_size = iv_size + 2 + data_size;

	uint32_t result = 0;

	byte_t zero_iv[16] = {0};
	byte_t message_iv[32] = {0};

	packet->data = malloc(total_data_size);

	if (packet->data == NULL)
	{
		return NULL;
	}

	packet->header = pgp_encode_packet_header(PGP_LEGACY_HEADER, PGP_SED, total_data_size);

	// Generate the IV
	result = pgp_rand(message_iv, iv_size);

	if (result != iv_size)
	{
		return 0;
	}

	// Last 2 octets
	message_iv[iv_size] = message_iv[iv_size - 2];
	message_iv[iv_size + 1] = message_iv[iv_size - 1];

	// Generate the iv
	pgp_cfb_encrypt(symmetric_key_algorithm_id, session_key, session_key_size, zero_iv, iv_size, message_iv, iv_size + 2, packet->data,
					iv_size + 2);

	// Encrypt the data
	pgp_cfb_encrypt(symmetric_key_algorithm_id, session_key, session_key_size, PTR_OFFSET(packet->data, 2), iv_size, data, data_size,
					PTR_OFFSET(packet->data, iv_size + 2), data_size);

	return packet;
}

size_t pgp_sed_packet_decrypt(pgp_sed_packet *packet, byte_t symmetric_key_algorithm_id, void *session_key, size_t session_key_size,
							  void *data, size_t data_size)
{
	size_t iv_size = pgp_symmetric_cipher_block_size(symmetric_key_algorithm_id);
	size_t plaintext_size = packet->header.body_size - (iv_size + 2);

	byte_t zero_iv[16] = {0};
	byte_t message_iv[32] = {0};

	if (data_size < plaintext_size)
	{
		return 0;
	}

	// Decrypt the iv
	pgp_cfb_decrypt(symmetric_key_algorithm_id, session_key, session_key_size, zero_iv, iv_size, packet->data, iv_size + 2, message_iv,
					iv_size + 2);

	// Check if key is correct
	if (message_iv[iv_size + 1] != message_iv[iv_size - 1] || message_iv[iv_size] != message_iv[iv_size - 2])
	{
		return 0;
	}

	// Decrypt the data
	pgp_cfb_decrypt(symmetric_key_algorithm_id, session_key, session_key_size, PTR_OFFSET(packet->data, 2), iv_size,
					PTR_OFFSET(packet->data, iv_size + 2), plaintext_size, data, plaintext_size);

	return plaintext_size;
}

pgp_sed_packet *pgp_sed_packet_read(void *data, size_t size)
{
	pgp_sed_packet *packet = NULL;
	pgp_packet_header header = {0};

	header = pgp_packet_header_read(data, size);

	if (pgp_packet_get_type(header.tag) != PGP_SED)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_sed_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	packet->data = malloc(header.body_size);

	if (packet->data == NULL)
	{
		free(packet);
		return NULL;
	}

	// Copy the header
	packet->header = header;

	// Copy the packet data.
	memcpy(packet->data, PTR_OFFSET(data, header.header_size), packet->header.body_size);

	return packet;
}

size_t pgp_sed_packet_write(pgp_sed_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// N bytes of symmetrically encryrpted data

	required_size = packet->header.header_size + packet->header.body_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Data
	memcpy(out + pos, packet->data, packet->header.body_size);
	pos += packet->header.body_size;

	return pos;
}

static size_t pgp_seipd_packet_v1_write(pgp_seipd_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number with value 1.
	// N octets of symmetrically encryrpted data

	required_size = packet->header.header_size + 1 + packet->data_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// Data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	return pos;
}

static size_t pgp_seipd_packet_v2_write(pgp_seipd_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number with value 2.
	// A 1-octet symmetric key algorithm.
	// A 1-octet AEAD algorithm.
	// A 1-octet chunk size.
	// A 32-octets of salt.
	// Symmetrically encryrpted data
	// Authentication tag

	required_size = packet->header.header_size + 1 + 1 + 1 + 1 + 32 + packet->data_size + packet->tag_size;

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

	// 32-octets of salt
	memcpy(out + pos, packet->salt, 32);
	pos += 32;

	// Data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	// Tag
	memcpy(out + pos, packet->tag, packet->tag_size);
	pos += packet->tag_size;

	return pos;
}

static pgp_seipd_packet *pgp_seipd_packet_v1_encrypt(pgp_seipd_packet *packet, void *session_key, size_t session_key_size, void *data,
													 size_t data_size)
{
	byte_t block_size = pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id);

	byte_t *pdata = NULL;

	byte_t zero_iv[16] = {0};
	byte_t prefix[32] = {0};
	byte_t mdc[SHA1_HASH_SIZE] = {0};

	packet->data_size = block_size + 2 + data_size + 2 + SHA1_HASH_SIZE;
	packet->data = malloc(packet->data_size);

	if (packet->data == NULL)
	{
		return NULL;
	}

	pdata = packet->data;

	// Generate random prefix of block size
	pgp_rand(prefix, block_size);

	// Copy the prefix
	memcpy(packet->data, prefix, block_size);

	// Copy last 2 octets
	pdata[block_size] = prefix[block_size - 2];
	pdata[block_size + 1] = prefix[block_size - 1];

	// Copy the remaining plaintext
	memcpy(PTR_OFFSET(packet->data, block_size + 2), data, data_size);

	// Append the trailer
	pdata[block_size + 2 + data_size] = 0xD3;
	pdata[block_size + 2 + data_size + 1] = 0x14;

	// Hash first
	sha1_hash(packet->data, packet->data_size, mdc);

	// Copy the hash to the end
	memcpy(PTR_OFFSET(packet->data, packet->data_size - SHA1_HASH_SIZE), mdc, SHA1_HASH_SIZE);

	// Encrypt
	pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, session_key, session_key_size, zero_iv, block_size, packet->data, packet->data_size,
					packet->data, packet->data_size);

	// Always create V1 packets with legacy format headers
	packet->header = pgp_encode_packet_header(PGP_LEGACY_HEADER, PGP_SEIPD, packet->data_size + 1);

	return packet;
}

static pgp_seipd_packet *pgp_seipd_packet_v2_encrypt(pgp_seipd_packet *packet, byte_t salt[32], void *session_key, size_t session_key_size,
													 void *data, size_t data_size)
{
	uint32_t chunk_size = 1u << (packet->chunk_size + 6);
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	byte_t iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);

	size_t in_pos = 0;
	size_t out_pos = 0;
	size_t count = 0;

	byte_t derived_key[48] = {0};
	byte_t iv[16] = {0};
	byte_t info[5] = {0};

	byte_t *in = data;
	byte_t *out = NULL;

	info[0] = packet->header.tag;
	info[1] = packet->version;
	info[2] = packet->symmetric_key_algorithm_id;
	info[3] = packet->aead_algorithm_id;
	info[4] = packet->chunk_size;

	// Copy the salt
	memcpy(packet->salt, salt, 32);

	// Derive the message key
	hkdf(HASH_SHA256, session_key, session_key_size, salt, 32, info, 5, derived_key, key_size + iv_size - 8);

	// Copy part of the it as IV
	memcpy(iv, PTR_OFFSET(derived_key, key_size), iv_size - 8);

	// Encrypt the data paritioned by chunk size
	packet->data_size = CEIL_DIV(data_size, chunk_size) * (chunk_size + PGP_AEAD_TAG_SIZE);
	packet->data = malloc(packet->data_size);

	if (packet->data == NULL)
	{
		return NULL;
	}

	out = packet->data;

	while (in_pos < data_size)
	{
		size_t result = 0;
		uint32_t in_size = MIN(chunk_size, data_size - in_pos);
		size_t count_be = BSWAP_64(count);

		memcpy(PTR_OFFSET(iv, iv_size - 8), &count_be, 8);

		// Encrypt the data
		result = pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size, iv, iv_size, info,
								  5, in + in_pos, in_size, out + out_pos, in_size, out + (out_pos + in_size), PGP_AEAD_TAG_SIZE);

		if (result == 0)
		{
			return NULL;
		}

		in_pos += in_size;
		out_pos += in_size + PGP_AEAD_TAG_SIZE;
		++count;
	}

	// Final authentication tag
	byte_t aad[16] = {0};
	byte_t *pc = (byte_t *)count;

	packet->tag_size = PGP_AEAD_TAG_SIZE;

	// Same as info
	aad[0] = info[0];
	aad[1] = info[1];
	aad[2] = info[2];
	aad[3] = info[3];
	aad[4] = info[4];

	// Store number of chunks as 8 byte big endian
	aad[5] = pc[7];
	aad[6] = pc[6];
	aad[7] = pc[5];
	aad[8] = pc[4];
	aad[9] = pc[3];
	aad[10] = pc[2];
	aad[11] = pc[1];
	aad[12] = pc[0];

	pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size,
					 PTR_OFFSET(derived_key, key_size), (iv_size - 8), aad, 13, NULL, 0, NULL, 0, packet->tag, PGP_AEAD_TAG_SIZE);

	// Always create V2 packets with new format headers
	packet->header = pgp_encode_packet_header(PGP_HEADER, PGP_SEIPD, 4 + 32 + packet->tag_size + packet->data_size);

	return packet;
}

static size_t pgp_seipd_packet_v1_decrypt(pgp_seipd_packet *packet, void *session_key, size_t session_key_size, void *data,
										  size_t data_size)
{
	byte_t block_size = pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id);
	size_t plaintext_size = packet->data_size - (block_size + 4 + SHA1_HASH_SIZE);

	byte_t *pdata = NULL;
	void *temp = NULL;

	byte_t zero_iv[16] = {0};
	byte_t mdc[SHA1_HASH_SIZE] = {0};

	if (data_size < plaintext_size)
	{
		return 0;
	}

	// We really don't have to allocate memory here. This is a legacy packet, so no issues.
	temp = malloc(packet->data_size);

	if (temp == NULL)
	{
		return 0;
	}

	pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, session_key, session_key_size, zero_iv, block_size, packet->data, packet->data_size,
					temp, packet->data_size);

	// Do checking
	pdata = temp;

	// Quick
	if (pdata[block_size] != pdata[block_size - 2] || pdata[block_size + 1] != pdata[block_size - 1])
	{
		free(temp);
		return 0;
	}

	// Hash
	sha1_hash(temp, packet->data_size - SHA1_HASH_SIZE, mdc);

	if (memcmp(mdc, PTR_OFFSET(packet->data, packet->data_size - SHA1_HASH_SIZE), SHA1_HASH_SIZE) != 0)
	{
		free(temp);
		return 0;
	}

	// Copy the decrypted text
	memcpy(data, PTR_OFFSET(temp, block_size + 2), plaintext_size);
	free(temp);

	return plaintext_size;
}

static size_t pgp_seipd_packet_v2_decrypt(pgp_seipd_packet *packet, void *session_key, size_t session_key_size, void *data,
										  size_t data_size)
{
	uint32_t chunk_size = 1u << (packet->chunk_size + 6);
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	byte_t iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);

	size_t in_pos = 0;
	size_t out_pos = 0;
	size_t count = 0;

	byte_t tag[PGP_AEAD_TAG_SIZE] = {0};
	byte_t derived_key[48] = {0};
	byte_t iv[16] = {0};
	byte_t info[5] = {0};

	byte_t *in = packet->data;
	byte_t *out = data;

	info[0] = packet->header.tag;
	info[1] = packet->version;
	info[2] = packet->symmetric_key_algorithm_id;
	info[3] = packet->aead_algorithm_id;
	info[4] = packet->chunk_size;

	// Derive the message key
	hkdf(HASH_SHA256, session_key, session_key_size, packet->salt, 32, info, 5, derived_key, key_size + iv_size - 8);

	// Copy part of the it as IV
	memcpy(iv, PTR_OFFSET(derived_key, key_size), iv_size - 8);

	// Decrypt the data paritioned by chunk size + tag size
	while (in_pos < packet->data_size)
	{
		size_t result = 0;
		uint32_t in_size = MIN(chunk_size + packet->tag_size, data_size - in_pos);
		size_t count_be = BSWAP_64(count);

		memcpy(PTR_OFFSET(iv, iv_size - 8), &count_be, 8);

		// Decrypt the data
		result = pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size, iv, iv_size, info,
								  5, in + in_pos, in_size, out + out_pos, in_size, tag, PGP_AEAD_TAG_SIZE);

		if (result == 0)
		{
			return 0;
		}

		in_pos += in_size;
		out_pos += in_size - PGP_AEAD_TAG_SIZE;
		++count;
	}

	// Final authentication tag
	byte_t aad[16] = {0};
	byte_t *pc = (byte_t *)count;

	packet->tag_size = PGP_AEAD_TAG_SIZE;

	// Same as info
	aad[0] = info[0];
	aad[1] = info[1];
	aad[2] = info[2];
	aad[3] = info[3];
	aad[4] = info[4];

	// Store number of chunks as 8 byte big endian
	aad[5] = pc[7];
	aad[6] = pc[6];
	aad[7] = pc[5];
	aad[8] = pc[4];
	aad[9] = pc[3];
	aad[10] = pc[2];
	aad[11] = pc[1];
	aad[12] = pc[0];

	pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, derived_key, key_size,
					 PTR_OFFSET(derived_key, key_size), (iv_size - 8), aad, 13, NULL, 0, NULL, 0, tag, PGP_AEAD_TAG_SIZE);

	if (memcmp(tag, packet->tag, PGP_AEAD_TAG_SIZE) != 0)
	{
		return 0;
	}

	return out_pos;
}

pgp_seipd_packet *pgp_seipd_packet_new(byte_t version, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id, byte_t chunk_size)
{
	pgp_seipd_packet *packet = NULL;

	if (version != PGP_SEIPD_V2 && version != PGP_SEIPD_V1)
	{
		return NULL;
	}

	if (version == PGP_SEIPD_V2)
	{
		if (chunk_size > 16)
		{
			return NULL;
		}
	}

	packet = malloc(sizeof(pgp_seipd_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_seipd_packet));

	if (version == PGP_SEIPD_V2)
	{
		packet->version = PGP_SEIPD_V2;
		packet->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
		packet->aead_algorithm_id = aead_algorithm_id;
		packet->chunk_size = chunk_size;
	}
	else
	{
		packet->version = PGP_SEIPD_V1;
		packet->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
	}

	return packet;
}

void pgp_seipd_packet_delete(pgp_seipd_packet *packet)
{
	free(packet->data);
	free(packet);
}

pgp_seipd_packet *pgp_seipd_packet_encrypt(pgp_seipd_packet *packet, byte_t salt[32], void *session_key, size_t session_key_size,
										   void *data, size_t data_size)
{

	switch (packet->version)
	{
	case PGP_SEIPD_V1:
		return pgp_seipd_packet_v1_encrypt(packet, session_key, session_key_size, data, data_size);
	case PGP_SEIPD_V2:
		return pgp_seipd_packet_v2_encrypt(packet, salt, session_key, session_key_size, data, data_size);
	}

	return NULL;
}

size_t pgp_seipd_packet_decrypt(pgp_seipd_packet *packet, void *session_key, size_t session_key_size, void *data, size_t data_size)
{

	switch (packet->version)
	{
	case PGP_SEIPD_V1:
		return pgp_seipd_packet_v1_decrypt(packet, session_key, session_key_size, data, data_size);
	case PGP_SEIPD_V2:
		return pgp_seipd_packet_v2_decrypt(packet, session_key, session_key_size, data, data_size);
	}

	return 0;
}

pgp_seipd_packet *pgp_seipd_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_seipd_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_SEIPD)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_seipd_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_aead_packet));

	// Copy the header
	packet->header = header;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);

	if (packet->version == PGP_SEIPD_V2)
	{
		// 1 octet symmetric key algorithm
		LOAD_8(&packet->symmetric_key_algorithm_id, in + pos);
		pos += 1;

		// 1 octet AEAD algorithm
		LOAD_8(&packet->aead_algorithm_id, in + pos);
		pos += 1;

		// 1 octet chunk size
		LOAD_8(&packet->chunk_size, in + pos);
		pos += 1;

		// 32-octets of salt
		memcpy(packet->salt, in + pos, 32);
		pos += 32;

		// Data
		packet->data_size = packet->header.body_size - pos - PGP_AEAD_TAG_SIZE;
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			free(packet);
			return NULL;
		}

		memcpy(packet->data, in + pos, packet->data_size);
		pos += packet->data_size;

		// Tag
		packet->tag_size = PGP_AEAD_TAG_SIZE;
		memcpy(packet->tag, in + pos, packet->tag_size);
		pos += packet->tag_size;
	}
	else if (packet->version == PGP_SEIPD_V1)
	{
		// Data
		packet->data_size = packet->header.body_size - 1;
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			free(packet);
			return NULL;
		}

		memcpy(packet->data, in + pos, packet->data_size);
		pos += packet->data_size;
	}
	else
	{
		// Unknown version
		free(packet);
		return NULL;
	}

	return packet;
}

size_t pgp_seipd_packet_write(pgp_seipd_packet *packet, void *ptr, size_t size)
{
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

pgp_aead_packet *pgp_aead_packet_new(byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id, byte_t chunk_size)
{
	pgp_aead_packet *packet = NULL;

	packet = malloc(sizeof(pgp_aead_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_aead_packet));

	packet->version = PGP_AEAD_V1;
	packet->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
	packet->aead_algorithm_id = aead_algorithm_id;
	packet->chunk_size = chunk_size;

	return packet;
}

void pgp_aead_packet_delete(pgp_aead_packet *packet)
{
	free(packet->data);
	free(packet);
}

pgp_aead_packet *pgp_aead_packet_encrypt(pgp_aead_packet *packet, byte_t iv[16], byte_t iv_size, void *session_key, size_t session_key_size,
										 void *data, size_t data_size);
size_t pgp_aead_packet_decrypt(pgp_aead_packet *packet, void *session_key, size_t session_key_size, void *data, size_t data_size);

pgp_aead_packet *pgp_aead_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_aead_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;
	byte_t iv_size = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_AEAD)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_aead_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_aead_packet));

	// Copy the header
	packet->header = header;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);

	if (packet->version == PGP_AEAD_V1)
	{
		// 1 octet symmetric key algorithm
		LOAD_8(&packet->symmetric_key_algorithm_id, in + pos);
		pos += 1;

		// 1 octet AEAD algorithm
		LOAD_8(&packet->aead_algorithm_id, in + pos);
		pos += 1;

		// 1 octet chunk size
		LOAD_8(&packet->chunk_size, in + pos);
		pos += 1;

		iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);

		// IV
		memcpy(packet->iv, in + pos, iv_size);
		pos += iv_size;

		// Data
		packet->data_size = packet->header.body_size - pos - PGP_AEAD_TAG_SIZE;
		packet->data = malloc(packet->data_size);

		if (packet->data == NULL)
		{
			free(packet);
			return NULL;
		}

		memcpy(packet->data, in + pos, packet->data_size);
		pos += packet->data_size;

		// Tag
		packet->tag_size = PGP_AEAD_TAG_SIZE;
		memcpy(packet->tag, in + pos, packet->tag_size);
		pos += packet->tag_size;
	}
	else
	{
		// Unknown version
		free(packet);
		return NULL;
	}

	return packet;
}

size_t pgp_aead_packet_write(pgp_aead_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	byte_t iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);

	// A 1-octet version number with value 1.
	// A 1-octet symmetric key algorithm.
	// A 1-octet AEAD algorithm.
	// A 1-octet chunk size.
	// A 12/15/16-octets of IV.
	// Symmetrically encryrpted data
	// Authentication tag

	required_size = packet->header.header_size + 1 + 1 + 1 + 1 + iv_size + packet->data_size + packet->tag_size;

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
	memcpy(out + pos, packet->iv, iv_size);
	pos += iv_size;

	// Data
	memcpy(out + pos, packet->data, packet->data_size);
	pos += packet->data_size;

	// Tag
	memcpy(out + pos, packet->tag, packet->tag_size);
	pos += packet->tag_size;

	return pos;
}
