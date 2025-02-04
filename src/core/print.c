/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <seipd.h>
#include <session.h>

#include <stdio.h>
#include <string.h>

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static size_t pgp_packet_header_print(pgp_packet_header header, void *str, size_t size)
{
	pgp_packet_header_format format = PGP_PACKET_HEADER_FORMAT(header.tag);
	pgp_packet_type type = pgp_packet_get_type(header.tag);

	byte_t *out = str;
	size_t pos = 0;

	switch (type)
	{
	case PGP_PKESK:
		memcpy(PTR_OFFSET(str, pos), "Public Key Encrypted Session Key Packet (Tag 1)", 47);
		pos += 47;
		break;
	case PGP_SIG:
		memcpy(PTR_OFFSET(str, pos), "Signature Packet (Tag 2)", 24);
		pos += 25;
		break;
	case PGP_SKESK:
		memcpy(PTR_OFFSET(str, pos), "Symmetric Key Encrypted Session Key Packet (Tag 3)", 50);
		pos += 51;
		break;
	case PGP_OPS:
		memcpy(PTR_OFFSET(str, pos), "One-Pass Signature Packet (Tag 4)", 33);
		pos += 34;
		break;
	case PGP_SECKEY:
		memcpy(PTR_OFFSET(str, pos), "Secret Key Packet (Tag 5)", 25);
		pos += 26;
		break;
	case PGP_PUBKEY:
		memcpy(PTR_OFFSET(str, pos), "Public Key Packet (Tag 6)", 25);
		pos += 26;
		break;
	case PGP_SECSUBKEY:
		memcpy(PTR_OFFSET(str, pos), "Secret Subkey Packet (Tag 7)", 28);
		pos += 29;
		break;
	case PGP_COMP:
		memcpy(PTR_OFFSET(str, pos), "Compressed Data Packet (Tag 8)", 30);
		pos += 30;
		break;
	case PGP_SED:
		memcpy(PTR_OFFSET(str, pos), "Symmetrically Encrypted Data Packet (Tag 9)", 43);
		pos += 44;
		break;
	case PGP_MARKER:
		memcpy(PTR_OFFSET(str, pos), "Marker Packet (Tag 10)", 22);
		pos += 23;
		break;
	case PGP_LIT:
		memcpy(PTR_OFFSET(str, pos), "Literal Data Packet (Tag 11)", 28);
		pos += 28;
		break;
	case PGP_TRUST:
		memcpy(PTR_OFFSET(str, pos), "Trust Packet (Tag 12)", 21);
		pos += 22;
		break;
	case PGP_UID:
		memcpy(PTR_OFFSET(str, pos), "User ID Packet (Tag 13)", 23);
		pos += 24;
		break;
	case PGP_PUBSUBKEY:
		memcpy(PTR_OFFSET(str, pos), "Public Subkey Packet (Tag 14)", 29);
		pos += 30;
		break;
	case PGP_UAT:
		memcpy(PTR_OFFSET(str, pos), "User Attribute Packet (Tag 17)", 30);
		pos += 31;
		break;
	case PGP_SEIPD:
		memcpy(PTR_OFFSET(str, pos), "Symmetrically Encrypted and Integrity Protected Data Packet (Tag 18)", 68);
		pos += 68;
		break;
	case PGP_MDC:
		memcpy(PTR_OFFSET(str, pos), "Modification Detection Code Packet (Tag 19)", 45);
		pos += 45;
		break;
	case PGP_PADDING:
		memcpy(PTR_OFFSET(str, pos), "Padding Packet (Tag 21)", 23);
		pos += 24;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Packet (Tag %hhu)", header.tag);
	}

	if (format == PGP_LEGACY_HEADER)
	{
		memcpy(PTR_OFFSET(str, pos), " (Old)\n", 7);
		pos += 7;
	}
	else
	{
		out[pos] = '\n';
		pos += 1;
	}

	return pos;
}

static size_t pgp_public_key_algorithm_print(pgp_public_key_algorithms algorithm, void *str, size_t size)
{
	size_t pos = 0;

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		memcpy(PTR_OFFSET(str, pos), "RSA Encrypt (Tag 1)\n", 20);
		pos += 20;
		break;
	case PGP_RSA_ENCRYPT_ONLY:
		memcpy(PTR_OFFSET(str, pos), "RSA (Encrypt Only) (Tag 2)\n", 27);
		pos += 27;
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		memcpy(PTR_OFFSET(str, pos), "Elgamal (Encrypt Only) (Tag 16)\n", 32);
		pos += 32;
		break;
	case PGP_ECDH:
		memcpy(PTR_OFFSET(str, pos), "ECDH (Tag 18)\n", 14);
		pos += 14;
		break;
	case PGP_X25519:
		memcpy(PTR_OFFSET(str, pos), "X25519 (Tag 22)\n", 16);
		pos += 16;
		break;
	case PGP_X448:
		memcpy(PTR_OFFSET(str, pos), "X448 (Tag 23)\n", 14);
		pos += 14;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Public Key Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_signature_algorithm_print(pgp_public_key_algorithms algorithm, void *str, size_t size)
{
	size_t pos = 0;

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		memcpy(PTR_OFFSET(str, pos), "RSA Encrypt (Tag 1)\n", 20);
		pos += 20;
		break;
	case PGP_RSA_SIGN_ONLY:
		memcpy(PTR_OFFSET(str, pos), "RSA (Sign Only) (Tag 2)\n", 27);
		pos += 27;
		break;
	case PGP_DSA:
		memcpy(PTR_OFFSET(str, pos), "DSA (Tag 17)\n", 13);
		pos += 13;
		break;
	case PGP_ECDSA:
		memcpy(PTR_OFFSET(str, pos), "ECDSA (Tag 19)\n", 15);
		pos += 15;
		break;
	case PGP_EDDSA_LEGACY:
		memcpy(PTR_OFFSET(str, pos), "EdDSA (Legacy) (Tag 22)\n", 25);
		pos += 25;
		break;
	case PGP_ED25519:
		memcpy(PTR_OFFSET(str, pos), "Ed25519 (Tag 27)\n", 18);
		pos += 18;
		break;
	case PGP_ED448:
		memcpy(PTR_OFFSET(str, pos), "Ed448 (Tag 28)\n", 16);
		pos += 16;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Signature algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_symmetric_key_algorithm_print(pgp_symmetric_key_algorithms algorithm, void *str, size_t size)
{
	size_t pos = 0;

	switch (algorithm)
	{
	case PGP_PLAINTEXT:
		memcpy(PTR_OFFSET(str, pos), "Plaintext (Tag 0)\n", 18);
		pos += 18;
		break;
	case PGP_IDEA:
		memcpy(PTR_OFFSET(str, pos), "IDEA (Tag 1)\n", 13);
		pos += 13;
		break;
	case PGP_TDES:
		memcpy(PTR_OFFSET(str, pos), "TDES (Tag 2)\n", 13);
		pos += 13;
		break;
	case PGP_CAST5_128:
		memcpy(PTR_OFFSET(str, pos), "CAST5 (Tag 3)\n", 14);
		pos += 14;
		break;
	case PGP_BLOWFISH:
		memcpy(PTR_OFFSET(str, pos), "Blowfish (Tag 4)\n", 17);
		pos += 17;
		break;
	case PGP_AES_128:
		memcpy(PTR_OFFSET(str, pos), "AES-128 (Tag 7)\n", 16);
		pos += 16;
		break;
	case PGP_AES_192:
		memcpy(PTR_OFFSET(str, pos), "AES-192 (Tag 8)\n", 16);
		pos += 16;
		break;
	case PGP_AES_256:
		memcpy(PTR_OFFSET(str, pos), "AES-256 (Tag 9)\n", 16);
		pos += 16;
		break;
	case PGP_TWOFISH:
		memcpy(PTR_OFFSET(str, pos), "Twofish (Tag 10)\n", 17);
		pos += 17;
		break;
	case PGP_CAMELLIA_128:
		memcpy(PTR_OFFSET(str, pos), "Camellia-128 (Tag 11)\n", 21);
		pos += 21;
		break;
	case PGP_CAMELLIA_192:
		memcpy(PTR_OFFSET(str, pos), "Camellia-192 (Tag 12)\n", 21);
		pos += 21;
		break;
	case PGP_CAMELLIA_256:
		memcpy(PTR_OFFSET(str, pos), "Camellia-256 (Tag 13)\n", 21);
		pos += 21;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Symmetric Key Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_aead_algorithm_print(pgp_aead_algorithms algorithm, void *str, size_t size)
{
	size_t pos = 0;

	switch (algorithm)
	{
	case PGP_AEAD_EAX:
		memcpy(PTR_OFFSET(str, pos), "EAX (Tag 1)\n", 11);
		pos += 11;
		break;
	case PGP_AEAD_OCB:
		memcpy(PTR_OFFSET(str, pos), "OCB (Tag 2)\n", 11);
		pos += 11;
		break;
	case PGP_AEAD_GCM:
		memcpy(PTR_OFFSET(str, pos), "GCM (Tag 3)\n", 11);
		pos += 11;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown AEAD Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_hash_algorithm_print(pgp_hash_algorithms algorithm, void *str, size_t size)
{
	size_t pos = 0;

	switch (algorithm)
	{
	case PGP_MD5:
		memcpy(PTR_OFFSET(str, pos), "MD5 (Tag 1)\n", 11);
		pos += 11;
		break;
	case PGP_SHA1:
		memcpy(PTR_OFFSET(str, pos), "SHA-1 (Tag 2)\n", 13);
		pos += 13;
		break;
	case PGP_RIPEMD_160:
		memcpy(PTR_OFFSET(str, pos), "RIPEMD-160 (Tag 3)\n", 19);
		pos += 19;
		break;
	case PGP_SHA2_256:
		memcpy(PTR_OFFSET(str, pos), "SHA-256 (Tag 8)\n", 15);
		pos += 15;
		break;
	case PGP_SHA2_384:
		memcpy(PTR_OFFSET(str, pos), "SHA-384 (Tag 9)\n", 15);
		pos += 15;
		break;
	case PGP_SHA2_512:
		memcpy(PTR_OFFSET(str, pos), "SHA-512 (Tag 10)\n", 16);
		pos += 16;
		break;
	case PGP_SHA2_224:
		memcpy(PTR_OFFSET(str, pos), "SHA-224 (Tag 11)\n", 16);
		pos += 16;
		break;
	case PGP_SHA3_256:
		memcpy(PTR_OFFSET(str, pos), "SHA3-256 (Tag 12)\n", 17);
		pos += 17;
		break;
	case PGP_SHA3_512:
		memcpy(PTR_OFFSET(str, pos), "SHA3-512 (Tag 14)\n", 17);
		pos += 17;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Hash Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

size_t pgp_compresed_packet_print(pgp_compresed_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);

	memcpy(PTR_OFFSET(str, pos), "Compression Algorithm: ", 23);
	pos += 23;

	switch (packet->compression_algorithm_id)
	{
	case PGP_UNCOMPRESSED:
		memcpy(PTR_OFFSET(str, pos), "Uncompressed (Tag 0)\n", 21);
		pos += 21;
		break;
	case PGP_DEFALTE:
		memcpy(PTR_OFFSET(str, pos), "Deflate (Tag 1)\n", 16);
		pos += 16;
		break;
	case PGP_ZLIB:
		memcpy(PTR_OFFSET(str, pos), "ZLIB (Tag 2)\n", 13);
		pos += 13;
		break;
	case PGP_BZIP2:
		memcpy(PTR_OFFSET(str, pos), "BZIP2 (Tag 3)\n", 14);
		pos += 14;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown (Tag %hhu)\n", packet->compression_algorithm_id);
	}

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Data (%u bytes)\n", packet->header.body_size - 1);

	return pos;
}

size_t pgp_sed_packet_print(pgp_sed_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Encrypted Data (%u bytes)\n", packet->header.body_size);

	return pos;
}

size_t pgp_marker_packet_print(pgp_marker_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Marker: %c%c%c\n", packet->marker[0], packet->marker[1], packet->marker[2]);

	return pos;
}

size_t pgp_literal_packet_print(pgp_literal_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);

	memcpy(PTR_OFFSET(str, pos), "Format: ", 8);
	pos += 8;

	switch (packet->format)
	{
	case PGP_LITERAL_DATA_BINARY:
		memcpy(PTR_OFFSET(str, pos), "Binary (Tag 0)\n", 15);
		pos += 15;
		break;
	case PGP_LITERAL_DATA_TEXT:
		memcpy(PTR_OFFSET(str, pos), "Text (Tag 1)\n", 13);
		pos += 13;
		break;
	case PGP_LITERAL_DATA_UTF8:
		memcpy(PTR_OFFSET(str, pos), "UTF-8 (Tag 2)\n", 14);
		pos += 14;
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown (Tag %hhu)\n", packet->format);
	}

	// TODO format date
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "\nDate: %u\n", packet->date);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Filename (%u bytes): ", packet->filename_size);

	if (packet->filename_size > 0)
	{
		memcpy(PTR_OFFSET(str, pos), packet->filename, packet->filename_size);
		pos += packet->filename_size;
	}

	out[pos] = '\n';
	pos += 1;

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Data (%u bytes)\n", packet->data_size);

	return pos;
}

size_t pgp_user_id_packet_print(pgp_user_id_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);

	memcpy(PTR_OFFSET(str, pos), "User ID: ", 9);
	pos += 9;

	memcpy(PTR_OFFSET(str, pos), packet->user_id, packet->header.body_size);
	pos += packet->header.body_size;

	out[pos] = '\n';
	pos += 1;

	return pos;
}

size_t pgp_user_attribute_packet_print(pgp_user_attribute_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);

	for (uint16_t i = 0; i < packet->subpacket_count; ++i)
	{
		pgp_subpacket_header *subpacket_header = packet->subpackets[i];

		switch (subpacket_header->tag)
		{
		case PGP_USER_ATTRIBUTE_IMAGE:
		{
			pgp_user_attribute_image_subpacket *image_subpacket = (pgp_user_attribute_image_subpacket *)subpacket_header;
			uint32_t image_size = image_subpacket->header.body_size - 16;

			memcpy(PTR_OFFSET(str, pos), "User Attribute Image Subpacket (Tag 1)\n", 39);
			pos += 39;

			switch (image_subpacket->image_encoding)
			{
			case PGP_USER_ATTRIBUTE_IMAGE_JPEG:
			{
				memcpy(PTR_OFFSET(str, pos), "Image Encoding: JPEG (Tag 1)\n", 30);
				pos += 30;
			}
			break;
			default:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Image Encoding (Tag %hhu)\n", image_subpacket->image_encoding);
			}

			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Image Size: %u bytes\n", image_size);
		}
		break;
		default:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Subpacket (Tag %hhu) (%u bytes)\n", subpacket_header->tag,
							subpacket_header->body_size);
		}
	}

	return pos;
}

size_t pgp_padding_packet_print(pgp_padding_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Padding Data (%u bytes)\n", packet->header.body_size);

	return pos;
}

size_t pgp_mdc_packet_print(pgp_mdc_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size);

	memcpy(PTR_OFFSET(str, pos), "SHA-1 Hash: ", 12);
	pos += 12;

	for (uint8_t i = 0; i < 20; ++i)
	{
		byte_t a, b;

		a = packet->sha1_hash[i] / 16;
		b = packet->sha1_hash[i] % 16;

		out[pos++] = hex_table[a];
		out[pos++] = hex_table[b];
	}

	out[pos] = '\n';
	pos += 1;

	return pos;
}
