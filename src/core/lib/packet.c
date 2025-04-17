/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
#include <algorithms.h>
#include <packet.h>
#include <key.h>
#include <seipd.h>
#include <session.h>
#include <signature.h>

#include <bitscan.h>
#include <string.h>
#include <stdlib.h>

// Refer RFC 9580 - OpenPGP, Section 4.2 Packet Headers

static byte_t get_packet_header_size(pgp_packet_header_format format, byte_t partial, size_t size)
{
	if (format == PGP_HEADER)
	{
		if (partial)
		{
			return 1 + 1;
		}

		// New format packet lengths
		// 1 octed length
		if (size < 192)
		{
			return 1 + 1;
		}
		// 2 octet legnth
		else if (size < 8384)
		{
			return 1 + 2;
		}
		// 5 octet length
		else if (size < 4294967296)
		{
			return 1 + 5;
		}
		// Partial body
		else
		{
			return 1 + 1;
		}
	}
	else
	{
		if (partial)
		{
			return 1;
		}

		// Legacy format packet lengths
		// 1 octed length
		if (size < 256)
		{
			return 1 + 1;
		}
		// 2 octet legnth
		else if (size < 65536)
		{
			return 1 + 2;
		}
		// 4 octet length
		else if (size < 4294967296)
		{
			return 1 + 4;
		}
		// Partial body
		else
		{
			return 1;
		}
	}
}

static byte_t get_packet_tag(pgp_packet_header_format header_type, pgp_packet_type packet_type, byte_t partial, size_t size)
{
	byte_t tag = 0;

	if (header_type == PGP_HEADER)
	{
		tag = 0xC0 | (byte_t)packet_type;
	}
	else
	{
		// Old format packet
		tag = 0x80 | ((byte_t)packet_type << 2);

		if (partial)
		{
			goto partial_body;
		}

		// 1 octed length
		if (size < 256)
		{
			tag |= 0;
		}
		// 2 octet legnth
		else if (size < 65536)
		{
			tag |= 1;
		}
		// 4 octet length
		else if (size < 4294967296)
		{
			tag |= 2;
		}
		// Partial body
		else
		{
		partial_body:
			tag |= 3;
		}
	}

	return tag;
}

pgp_packet_header pgp_encode_packet_header(pgp_packet_header_format header_format, pgp_packet_type packet_type, size_t body_size)
{
	pgp_packet_header header = {0};

	header.tag = get_packet_tag(header_format, packet_type, 0, body_size);
	header.header_size = get_packet_header_size(header_format, 0, body_size);

	if (body_size > 4294967295)
	{
		header.body_size = 0;
		header.partial = 1;
	}
	else
	{
		header.body_size = body_size;
	}

	return header;
}

pgp_subpacket_header pgp_encode_subpacket_header(byte_t type, byte_t set_critical, uint32_t body_size)
{
	pgp_subpacket_header header = {0};
	uint32_t total_size = 0;

	header.tag = type | ((set_critical & 0x1) << 7);
	header.body_size = body_size;

	total_size = body_size + 1; // Include tag

	// 1,2, or 5 octets of subpacket length
	// 1 octed length
	if (total_size < 192)
	{
		header.header_size = 2;
	}
	// 2 octet legnth
	else if (total_size < 8384)
	{
		header.header_size = 3;
	}
	// 5 octet length
	else
	{
		header.header_size = 6;
	}

	return header;
}

pgp_packet_type pgp_packet_get_type(byte_t tag)
{
	pgp_packet_type ptype = 0;

	// Bit 6 and 7 are set
	if ((tag & 0xC0) == 0xC0)
	{
		ptype = tag & 0x3F;
	}
	else
	{
		ptype = (tag >> 2) & 0x0F;
	}

	switch (ptype)
	{
	case PGP_PKESK:
	case PGP_SIG:
	case PGP_SKESK:
	case PGP_OPS:
	case PGP_SECKEY:
	case PGP_PUBKEY:
	case PGP_SECSUBKEY:
	case PGP_COMP:
	case PGP_SED:
	case PGP_MARKER:
	case PGP_LIT:
	case PGP_TRUST:
	case PGP_UID:
	case PGP_PUBSUBKEY:
	case PGP_UAT:
	case PGP_SEIPD:
	case PGP_MDC:
	case PGP_AEAD:
	case PGP_PADDING:
	case PGP_KEYDEF:
	case PGP_KEYRING:
		break;
	default:
		// Error
		ptype = PGP_RESERVED;
	}

	return ptype;
}

uint32_t pgp_subpacket_stream_octets(pgp_stream_t *stream)
{
	pgp_subpacket_header *header = NULL;
	uint32_t count = 0;

	if (stream == NULL)
	{
		return 0;
	}

	for (uint16_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];
		count += header->body_size + header->header_size;
	}

	return count;
}

pgp_packet_header pgp_packet_header_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_packet_header error = {0};
	pgp_packet_header header = {0};
	pgp_packet_header_format format = PGP_HEADER;

	if (size < 1)
	{
		return error;
	}

	// Get the tag
	header.tag = in[0];
	format = PGP_PACKET_HEADER_FORMAT(header.tag);

	// New format packet
	if (format == PGP_HEADER)
	{
		// 5 octet length
		if (in[1] == 255)
		{
			if (size < 6)
			{
				return error;
			}

			header.header_size = 6;
			header.body_size = (((uint32_t)in[2] << 24) | ((uint32_t)in[3] << 16) | ((uint32_t)in[4] << 8) | (uint32_t)in[5]);
		}
		// Partial body length
		else if (in[1] >= 224 && in[1] <= 254)
		{
			if (size < 2)
			{
				return error;
			}

			header.header_size = 2;
			header.partial = 1;
			header.body_size = (uint32_t)1 << (in[1] & 0x1F);
		}
		// 2 octet legnth
		else if (in[1] >= 192 && in[1] <= 223)
		{
			if (size < 3)
			{
				return error;
			}

			header.header_size = 3;
			header.body_size = ((in[1] - 192) << 8) + in[2] + 192;
		}
		// 1 octed length
		else // if (pdata[1] < 192)
		{
			if (size < 2)
			{
				return error;
			}

			header.header_size = 2;
			header.body_size = in[1];
		}
	}
	else if (format == PGP_LEGACY_HEADER)
	{
		switch (header.tag & 0x3)
		{
		// 1 octed length
		case 0:
		{
			header.header_size = 2;
			header.body_size = in[1];
		}
		break;
		// 2 octet legnth
		case 1:
		{
			if (size < 3)
			{
				return error;
			}

			header.header_size = 3;
			header.body_size = ((uint32_t)in[1] << 8) + (uint32_t)in[2];
		}
		break;
		// 4 octet length
		case 2:
		{
			if (size < 5)
			{
				return error;
			}

			header.header_size = 5;
			header.body_size = ((uint32_t)in[1] << 24) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 8) | (uint32_t)in[4];
		}
		break;
		// Legacy partial packets.
		case 3:
		{
			// For legacy partial packets. Assume that the packet boundary is at the end of data.
			header.header_size = 1;
			header.body_size = size - 1;
		}
		break;
		}
	}
	else
	{
		return error;
	}

	return header;
}

uint32_t pgp_packet_header_write(pgp_packet_header *header, void *ptr)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	if (PGP_PACKET_HEADER_FORMAT(header->tag) == PGP_HEADER)
	{
		// 1 byte tag
		LOAD_8(out + pos, &header->tag);
		pos += 1;

		// Partial body length
		if (header->partial)
		{
			uint8_t size = BSR_32(header->body_size) + 224;

			LOAD_8(out + pos, &size);
			pos += 1;
		}

		// 1 octed length
		if (header->body_size < 192)
		{
			uint8_t size = (uint8_t)header->body_size;

			LOAD_8(out + pos, &size);
			pos += 1;
		}
		// 2 octet legnth
		else if (header->body_size < 8384)
		{
			uint16_t size = (uint16_t)header->body_size - 192;
			uint8_t o1 = (size >> 8) + 192;
			uint8_t o2 = (size & 0xFF);

			LOAD_8(out + pos, &o1);
			pos += 1;

			LOAD_8(out + pos, &o2);
			pos += 1;
		}
		// 5 octet length
		else
		{
			// 1st octet is 255
			uint8_t byte = 255;
			uint32_t size = BSWAP_32((uint32_t)header->body_size);

			LOAD_8(out + pos, &byte);
			pos += 1;

			LOAD_32(out + pos, &size);
			pos += 4;
		}
	}
	else
	{
		// 1 byte tag.
		LOAD_8(out + pos, &header->tag);
		pos += 1;

		// Partial body length
		if (header->partial)
		{
			return pos;
		}

		// 1 octed length
		if (header->body_size < 256)
		{
			uint8_t size = (uint8_t)header->body_size;

			LOAD_8(out + pos, &size);
			pos += 1;
		}
		// 2 octet legnth
		else if (header->body_size < 65536)
		{
			uint16_t size = BSWAP_16((uint16_t)header->body_size);

			LOAD_16(out + pos, &size);
			pos += 2;
		}
		// 4 octet length
		else if (header->body_size < 4294967296)
		{
			uint32_t size = BSWAP_32((uint32_t)header->body_size);

			LOAD_32(out + pos, &size);
			pos += 4;
		}
	}

	return pos;
}

pgp_subpacket_header pgp_subpacket_header_read(void *data, size_t size)
{
	pgp_subpacket_header header = {0};
	pgp_subpacket_header error = {0};

	byte_t *in = data;

	// 1,2, or 5 octets of subpacket length
	// 5 octet length
	if (in[0] >= 255)
	{
		if (size < 6)
		{
			return error;
		}

		header.header_size = 6;
		header.body_size = (((uint32_t)in[1] << 24) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 8) | (uint32_t)in[4]);
	}
	// 2 octet legnth
	else if (in[0] >= 192 && in[0] <= 233)
	{
		if (size < 3)
		{
			return error;
		}

		header.header_size = 3;
		header.body_size = ((in[0] - 192) << 8) + in[1] + 192;
	}
	// 1 octed length
	else if (in[0] < 192)
	{
		if (size < 2)
		{
			return error;
		}

		header.header_size = 2;
		header.body_size = in[0];
	}

	// 1 octet subpacket type
	header.tag = in[header.header_size - 1];
	header.body_size -= 1; // Exclude the subpacket tag

	return header;
}

uint32_t pgp_subpacket_header_write(pgp_subpacket_header *header, void *ptr)
{
	byte_t *out = ptr;
	uint32_t pos = 0;
	uint32_t total_size = header->body_size + 1; // Include tag

	// 1,2, or 5 octets of subpacket length
	// 1 octed length
	if (total_size < 192)
	{
		uint8_t size = (uint8_t)total_size;

		LOAD_8(out + pos, &size);
		pos += 1;
	}
	// 2 octet legnth
	else if (total_size < 8384)
	{
		uint16_t size = (uint16_t)total_size - 192;
		uint8_t o1 = (size >> 8) + 192;
		uint8_t o2 = (size & 0xFF);

		LOAD_8(out + pos, &o1);
		pos += 1;

		LOAD_8(out + pos, &o2);
		pos += 1;
	}
	// 5 octet length
	else
	{
		// 1st octet is 255
		uint8_t byte = 255;
		uint32_t size = BSWAP_32((uint32_t)total_size);

		LOAD_8(out + pos, &byte);
		pos += 1;

		LOAD_32(out + pos, &size);
		pos += 4;
	}

	// 1 octet subpacket type
	LOAD_8(out + pos, &header->tag);
	pos += 1;

	return pos;
}

pgp_partial_header pgp_partial_header_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_packet_header error = {0};
	pgp_packet_header header = {0};

	if (size < 1)
	{
		return error;
	}

	// Partial continue
	if (in[0] >= 224 && in[1] <= 254)
	{
		header.header_size = 1;
		header.partial = 1;
		header.body_size = (uint32_t)1 << (in[0] & 0x1F);
	}
	// Partial end
	else
	{
		// 5 octet length
		if (in[0] == 255)
		{
			if (size < 5)
			{
				return error;
			}

			header.header_size = 5;
			header.body_size = (((uint32_t)in[1] << 24) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 8) | (uint32_t)in[4]);
		}
		// 2 octet legnth
		else if (in[0] >= 192 && in[0] <= 223)
		{
			if (size < 2)
			{
				return error;
			}

			header.header_size = 2;
			header.body_size = ((in[0] - 192) << 8) + in[1] + 192;
		}
		// 1 octed length
		else // if (pdata[1] < 192)
		{
			header.header_size = 1;
			header.body_size = in[1];
		}
	}

	return header;
}

uint32_t pgp_partial_header_write(pgp_partial_header *header, void *ptr)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	// Partial continue
	if (header->partial)
	{
		uint8_t size = BSR_32(header->body_size) + 224;

		LOAD_8(out + pos, &size);
		pos += 1;
	}
	// Partial end
	else
	{
		// 1 octed length
		if (header->body_size < 192)
		{
			uint8_t size = (uint8_t)header->body_size;

			LOAD_8(out + pos, &size);
			pos += 1;
		}
		// 2 octet legnth
		else if (header->body_size < 8384)
		{
			uint16_t size = (uint16_t)header->body_size - 192;
			uint8_t o1 = (size >> 8) + 192;
			uint8_t o2 = (size & 0xFF);

			LOAD_8(out + pos, &o1);
			pos += 1;

			LOAD_8(out + pos, &o2);
			pos += 1;
		}
		// 5 octet length
		else
		{
			// 1st octet is 255
			uint8_t byte = 255;
			uint32_t size = BSWAP_32((uint32_t)header->body_size);

			LOAD_8(out + pos, &byte);
			pos += 1;

			LOAD_32(out + pos, &size);
			pos += 4;
		}
	}

	return pos;
}

// Internal read functions
pgp_error_t pgp_pkesk_packet_read_with_header(pgp_pkesk_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_skesk_packet_read_with_header(pgp_skesk_packet **packet, pgp_packet_header *header, void *data);

pgp_error_t pgp_signature_packet_read_with_header(pgp_signature_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_one_pass_signature_packet_read_with_header(pgp_one_pass_signature_packet **packet, pgp_packet_header *header, void *data);

pgp_error_t pgp_public_key_packet_read_with_header(pgp_key_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_secret_key_packet_read_with_header(pgp_key_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_key_packet_read_with_header(pgp_key_packet **packet, pgp_packet_header *header, void *data);

pgp_error_t pgp_sed_packet_read_with_header(pgp_sed_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_seipd_packet_read_with_header(pgp_seipd_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_aead_packet_read_with_header(pgp_aead_packet **packet, pgp_packet_header *header, void *data);

pgp_error_t pgp_compressed_packet_read_with_header(pgp_compresed_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_marker_packet_read_with_header(pgp_marker_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_literal_packet_read_with_header(pgp_literal_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_trust_packet_read_with_header(pgp_trust_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_user_id_packet_read_with_header(pgp_user_id_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_user_attribute_packet_read_with_header(pgp_user_attribute_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_mdc_packet_read_with_header(pgp_mdc_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_padding_packet_read_with_header(pgp_padding_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_keyring_packet_read_with_header(pgp_keyring_packet **packet, pgp_packet_header *header, void *data);
pgp_error_t pgp_unknown_packet_read_with_header(pgp_unknown_packet **packet, pgp_packet_header *header, void *data);

void *pgp_packet_read(void *data, size_t size)
{
	pgp_packet_header header = pgp_packet_header_read(data, size);
	pgp_packet_type type = pgp_packet_get_type(header.tag);

	pgp_error_t error = 0;
	void *packet = NULL;

	if (type == PGP_RESERVED)
	{
		// Invalid packet
		return NULL;
	}

	if (header.body_size == 0)
	{
		// Invalid packet
		return NULL;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		// Insufficient data
		return NULL;
	}

	switch (type)
	{
	case PGP_PKESK:
		error = pgp_pkesk_packet_read_with_header((pgp_pkesk_packet **)&packet, &header, data);
		return packet;
	case PGP_SIG:
		error = pgp_signature_packet_read_with_header((pgp_signature_packet **)&packet, &header, data);
		return packet;
	case PGP_SKESK:
		error = pgp_skesk_packet_read_with_header((pgp_skesk_packet **)&packet, &header, data);
		return packet;
	case PGP_OPS:
		error = pgp_one_pass_signature_packet_read_with_header((pgp_one_pass_signature_packet **)&packet, &header, data);
		return packet;
	case PGP_SECKEY:
		error = pgp_secret_key_packet_read_with_header((pgp_key_packet **)&packet, &header, data);
		return packet;
	case PGP_PUBKEY:
		error = pgp_public_key_packet_read_with_header((pgp_key_packet **)&packet, &header, data);
		return packet;
	case PGP_SECSUBKEY:
		error = pgp_secret_key_packet_read_with_header((pgp_key_packet **)&packet, &header, data);
		return packet;
	case PGP_COMP:
		error = pgp_compressed_packet_read_with_header((pgp_compresed_packet **)&packet, &header, data);
		return packet;
	case PGP_SED:
		error = pgp_sed_packet_read_with_header((pgp_sed_packet **)&packet, &header, data);
		return packet;
	case PGP_MARKER:
		error = pgp_marker_packet_read_with_header((pgp_marker_packet **)&packet, &header, data);
		return packet;
	case PGP_LIT:
		error = pgp_literal_packet_read_with_header((pgp_literal_packet **)&packet, &header, data);
		return packet;
	case PGP_TRUST:
		error = pgp_trust_packet_read_with_header((pgp_trust_packet **)&packet, &header, data);
		return packet;
	case PGP_UID:
		error = pgp_user_id_packet_read_with_header((pgp_user_id_packet **)&packet, &header, data);
		return packet;
	case PGP_PUBSUBKEY:
		error = pgp_public_key_packet_read_with_header((pgp_key_packet **)&packet, &header, data);
		return packet;
	case PGP_UAT:
		error = pgp_user_attribute_packet_read_with_header((pgp_user_attribute_packet **)&packet, &header, data);
		return packet;
	case PGP_SEIPD:
		error = pgp_seipd_packet_read_with_header((pgp_seipd_packet **)&packet, &header, data);
		return packet;
	case PGP_MDC:
		error = pgp_mdc_packet_read_with_header((pgp_mdc_packet **)&packet, &header, data);
		return packet;
	case PGP_AEAD:
		error = pgp_aead_packet_read_with_header((pgp_aead_packet **)&packet, &header, data);
		return packet;
	case PGP_PADDING:
		error = pgp_padding_packet_read_with_header((pgp_padding_packet **)&packet, &header, data);
		return packet;
	case PGP_KEYDEF:
		error = pgp_key_packet_read_with_header((pgp_key_packet **)&packet, &header, data);
		return packet;
	case PGP_KEYRING:
		error = pgp_keyring_packet_read_with_header((pgp_keyring_packet **)&packet, &header, data);
		return packet;
	default:
		error = pgp_unknown_packet_read_with_header((pgp_unknown_packet **)&packet, &header, data);
		return packet;
	}
}

size_t pgp_packet_write(void *packet, void *ptr, size_t size)
{
	pgp_packet_header *header = packet;
	pgp_packet_type ptype = pgp_packet_get_type(header->tag);

	switch (ptype)
	{
	case PGP_PKESK:
		return pgp_pkesk_packet_write(packet, ptr, size);
	case PGP_SIG:
		return pgp_signature_packet_write(packet, ptr, size);
	case PGP_SKESK:
		return pgp_skesk_packet_write(packet, ptr, size);
	case PGP_OPS:
		return pgp_one_pass_signature_packet_write(packet, ptr, size);
	case PGP_SECKEY:
		return pgp_secret_key_packet_write(packet, ptr, size);
	case PGP_PUBKEY:
		return pgp_public_key_packet_write(packet, ptr, size);
	case PGP_SECSUBKEY:
		return pgp_secret_key_packet_write(packet, ptr, size);
	case PGP_COMP:
		return pgp_compressed_packet_write(packet, ptr, size);
	case PGP_SED:
		return pgp_sed_packet_write(packet, ptr, size);
	case PGP_MARKER:
		return pgp_marker_packet_write(packet, ptr, size);
	case PGP_LIT:
		return pgp_literal_packet_write(packet, ptr, size);
	case PGP_TRUST:
		return pgp_trust_packet_write(packet, ptr, size);
	case PGP_UID:
		return pgp_user_id_packet_write(packet, ptr, size);
	case PGP_PUBSUBKEY:
		return pgp_public_key_packet_write(packet, ptr, size);
	case PGP_UAT:
		return pgp_user_attribute_packet_write(packet, ptr, size);
	case PGP_SEIPD:
		return pgp_seipd_packet_write(packet, ptr, size);
	case PGP_MDC:
		return pgp_mdc_packet_write(packet, ptr, size);
	case PGP_AEAD:
		return pgp_aead_packet_write(packet, ptr, size);
	case PGP_PADDING:
		return pgp_padding_packet_write(packet, ptr, size);
	case PGP_KEYDEF:
		return pgp_key_packet_write(packet, ptr, size);
	case PGP_KEYRING:
		return pgp_keyring_packet_write(packet, ptr, size);
	default:
		return pgp_unknown_packet_write(packet, ptr, size);
	}
}

size_t pgp_packet_print(void *packet, void *str, size_t size, uint32_t options)
{
	pgp_packet_header *header = packet;
	pgp_packet_type ptype = pgp_packet_get_type(header->tag);

	switch (ptype)
	{
	case PGP_PKESK:
		return pgp_pkesk_packet_print(packet, str, size, options);
	case PGP_SIG:
		return pgp_signature_packet_print(packet, str, size, options);
	case PGP_SKESK:
		return pgp_skesk_packet_print(packet, str, size);
	case PGP_OPS:
		return pgp_one_pass_signature_packet_print(packet, str, size);
	case PGP_SECKEY:
		return pgp_secret_key_packet_print(packet, str, size, options);
	case PGP_PUBKEY:
		return pgp_public_key_packet_print(packet, str, size, options);
	case PGP_SECSUBKEY:
		return pgp_secret_key_packet_print(packet, str, size, options);
	case PGP_COMP:
		return pgp_compressed_packet_print(packet, str, size);
	case PGP_SED:
		return pgp_sed_packet_print(packet, str, size);
	case PGP_MARKER:
		return pgp_marker_packet_print(packet, str, size);
	case PGP_LIT:
		return pgp_literal_packet_print(packet, str, size);
	case PGP_TRUST:
		return pgp_trust_packet_print(packet, str, size);
	case PGP_UID:
		return pgp_user_id_packet_print(packet, str, size);
	case PGP_PUBSUBKEY:
		return pgp_public_key_packet_print(packet, str, size, options);
	case PGP_UAT:
		return pgp_user_attribute_packet_print(packet, str, size);
	case PGP_SEIPD:
		return pgp_seipd_packet_print(packet, str, size);
	case PGP_MDC:
		return pgp_mdc_packet_print(packet, str, size);
	case PGP_AEAD:
		return pgp_aead_packet_print(packet, str, size);
	case PGP_PADDING:
		return pgp_padding_packet_print(packet, str, size);
	case PGP_KEYDEF:
		return pgp_key_packet_print(packet, str, size, options);
	case PGP_KEYRING:
		return pgp_keyring_packet_print(packet, str, size);
	default:
		return pgp_unknown_packet_print(packet, str, size);
	}
}

void pgp_packet_delete(void *packet)
{
	pgp_packet_header *header = packet;
	pgp_packet_type ptype = pgp_packet_get_type(header->tag);

	switch (ptype)
	{
	case PGP_PKESK:
		return pgp_pkesk_packet_delete(packet);
	case PGP_SIG:
		return pgp_signature_packet_delete(packet);
	case PGP_SKESK:
		return pgp_skesk_packet_delete(packet);
	case PGP_OPS:
		return pgp_one_pass_signature_packet_delete(packet);
	case PGP_SECKEY:
		return pgp_key_packet_delete(packet);
	case PGP_PUBKEY:
		return pgp_key_packet_delete(packet);
	case PGP_SECSUBKEY:
		return pgp_key_packet_delete(packet);
	case PGP_COMP:
		return pgp_compressed_packet_delete(packet);
	case PGP_SED:
		return pgp_sed_packet_delete(packet);
	case PGP_MARKER:
		return pgp_marker_packet_delete(packet);
	case PGP_LIT:
		return pgp_literal_packet_delete(packet);
	case PGP_TRUST:
		return pgp_trust_packet_delete(packet);
	case PGP_UID:
		return pgp_user_id_packet_delete(packet);
	case PGP_PUBSUBKEY:
		return pgp_key_packet_delete(packet);
	case PGP_UAT:
		return pgp_user_attribute_packet_delete(packet);
	case PGP_SEIPD:
		return pgp_seipd_packet_delete(packet);
	case PGP_MDC:
		return pgp_mdc_packet_delete(packet);
	case PGP_AEAD:
		return pgp_aead_packet_delete(packet);
	case PGP_PADDING:
		return pgp_padding_packet_delete(packet);
	case PGP_KEYDEF:
		return pgp_key_packet_delete(packet);
	case PGP_KEYRING:
		return pgp_keyring_packet_delete(packet);
	default:
		return free(packet);
	}
}

pgp_error_t pgp_partial_packet_read(pgp_partial_packet **packet, void *data, size_t size)
{
	pgp_partial_header header = pgp_partial_header_read(data, size);
	pgp_partial_packet *partial = NULL;

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	partial = malloc(sizeof(pgp_partial_packet));

	if (partial == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(partial, 0, sizeof(pgp_partial_packet));

	if (header.body_size != 0)
	{
		partial->data = malloc(header.body_size);

		if (partial->data == NULL)
		{
			free(partial);
			return PGP_NO_MEMORY;
		}
	}

	// Copy the header
	partial->header = header;

	// Copy the data
	if (header.body_size != 0)
	{
		memcpy(partial->data, PTR_OFFSET(data, header.header_size), header.body_size);
	}

	*packet = partial;

	return PGP_SUCCESS;
}

size_t pgp_partial_packet_write(pgp_partial_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// Padding data
	memcpy(out + pos, packet->data, packet->header.body_size);
	pos += packet->header.body_size;

	return pos;
}
