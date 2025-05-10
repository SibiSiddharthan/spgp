/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <key.h>
#include <signature.h>
#include <crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t encode_cleartext(byte_t *output, byte_t *input, size_t size)
{
	size_t pos = 0;

	// First character
	// Dash Escapes
	if (input[0] == '-')
	{
		output[pos++] = '-';
		output[pos++] = ' ';
		output[pos++] = '-';
	}

	// LF -> CRLF
	if (input[0] == '\n')
	{
		output[pos++] = '\r';
		output[pos++] = '\n';
	}

	for (size_t i = 1; i < size; ++i)
	{
		// Dash Escapes
		if (input[i] == '-' && input[i - 1] == '\n')
		{
			// Every line starting with '-' is prefixed with '-' and ' '.
			output[pos++] = '-';
			output[pos++] = ' ';
			output[pos++] = '-';
		}

		// LF -> CRLF
		if (input[i] == '\n' && input[i - 1] != '\r')
		{
			output[pos++] = '\r';
			output[pos++] = '\n';
		}

		output[pos++] = input[i];
	}

	return pos;
}

static size_t decode_cleartext(byte_t *output, byte_t *input, size_t size)
{
	size_t input_pos = 0;
	size_t output_pos = 0;

	// First character
	// Dash Escapes
	if (input[0] == '-')
	{
		input_pos += 2;
	}

	for (size_t i = input_pos; i < size; ++i)
	{
		// Dash Escapes
		if (input[i] == '-' && input[i - 1] == '\n')
		{
			// Every line starting with '-' is prefixed with '-' and ' '.
			i += 2;
		}

		output[output_pos++] = input[i];
	}

	return output_pos;
}

static pgp_hash_algorithms get_hash_algorithm(pgp_key_packet *packet)
{
	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
	{
		return PGP_SHA2_256;
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key;

		if (ROUND_UP(key->p->bits, 1024) == 1024)
		{
			return PGP_SHA1;
		}

		if (ROUND_UP(key->p->bits, 1024) == 2048)
		{
			return PGP_SHA2_224;
		}

		if (ROUND_UP(key->p->bits, 1024) == 3072)
		{
			return PGP_SHA2_256;
		}
	}
	break;
	case PGP_ECDSA:
	{
		pgp_ecdsa_key *key = packet->key;

		switch (key->curve)
		{
		case PGP_EC_NIST_P256:
			return PGP_SHA2_256;
		case PGP_EC_NIST_P384:
			return PGP_SHA2_384;
		case PGP_EC_NIST_P521:
			return PGP_SHA2_512;
		case PGP_EC_BRAINPOOL_256R1:
			return PGP_SHA2_256;
		case PGP_EC_BRAINPOOL_384R1:
			return PGP_SHA2_384;
		case PGP_EC_BRAINPOOL_512R1:
			return PGP_SHA2_512;
		}
	}
	break;
	case PGP_EDDSA:
	{
		pgp_eddsa_key *key = packet->key;

		if (key->curve == PGP_EC_ED25519)
		{
			return PGP_SHA2_256;
		}

		if (key->curve == PGP_EC_ED25519)
		{
			return PGP_SHA2_512;
		}
	}
	break;
	case PGP_ED25519:
	{
		return PGP_SHA2_256;
	}
	break;
	case PGP_ED448:
	{
		return PGP_SHA2_512;
	}
	break;
	default:
		return PGP_SHA2_512;
	}

	return PGP_SHA2_512;
}

#define IS_NUM(c)   ((c) >= 48 && (c) <= 57)
#define TO_NUM(c)   ((c) - 48)
#define TO_UPPER(c) ((c) & ~0x20)

static uint32_t parse_expiry(byte_t *in, byte_t length)
{
	uint32_t value = 0;

	for (byte_t i = 0; i < length; ++i)
	{
		if (IS_NUM(in[i]))
		{
			value = (value * 10) + TO_NUM(in[i]);
		}
		else
		{
			if (i != length - 1)
			{
				printf("Bad expiry");
				exit(1);
			}

			if (TO_UPPER(in[i]) == 'Y')
			{
				value = value * 31536000;
			}
			else if (TO_UPPER(in[i]) == 'D')
			{
				value = value * 86400;
			}
			else
			{
				printf("Bad expiry");
				exit(1);
			}
		}
	}

	// Seconds
	return value;
}

static pgp_sign_info *spgp_create_sign_info(pgp_key_packet *key, pgp_user_info *uinfo, pgp_signature_type type)
{
	pgp_sign_info *sinfo = NULL;
	pgp_hash_algorithms algorithm = get_hash_algorithm(key);

	// Create the structure
	PGP_CALL(pgp_sign_info_new(&sinfo, type, algorithm, 0, 0, 0, 0));

	// Set the signer
	PGP_CALL(pgp_sign_info_set_signer_id(sinfo, uinfo->uid, uinfo->uid_octets));

	// Generate salt
	if (key->version == PGP_KEY_V6)
	{
		sinfo->salt_size = pgp_rand(sinfo->salt, 32);
	}

	// Set expiration time
	if (command.expiration != NULL)
	{
		sinfo->expiry_seconds = parse_expiry(command.expiration, strlen(command.expiration));
	}

	// Set policies
	if (command.policy != NULL)
	{
		for (uint32_t i = 0; i < command.policy->count; ++i)
		{
			uint32_t size = strlen(command.policy->packets[i]);
			byte_t critical = ((byte_t *)command.policy->packets[i])[size - 1] == '!';

			PGP_CALL(pgp_sign_info_add_policy_uri(sinfo, critical, command.policy->packets[i], size - critical));
		}
	}

	// Set Keyservers
	if (command.keyserver != NULL)
	{
		for (uint32_t i = 0; i < command.keyserver->count; ++i)
		{
			uint32_t size = strlen(command.keyserver->packets[i]);
			byte_t critical = ((byte_t *)command.keyserver->packets[i])[size - 1] == '!';

			PGP_CALL(pgp_sign_info_add_keyserver_url(sinfo, critical, command.keyserver->packets[i], size - critical));
		}
	}

	// Set Notation
	if (command.notation != NULL)
	{
		for (uint32_t i = 0; i < command.notation->count; ++i)
		{
			uint32_t size = strlen(command.notation->packets[i]);
			byte_t critical = ((byte_t *)command.notation->packets[i])[size - 1] == '!';

			void *name = command.notation->packets[i];
			void *equal = memchr(name, '=', size);
			void *value = PTR_OFFSET(equal, 1);

			uint32_t name_size = (uint32_t)((uintptr_t)equal - (uintptr_t)name);
			uint32_t value_size = size - name_size - 1 - critical;

			PGP_CALL(pgp_sign_info_add_notation(sinfo, critical, PGP_NOTATION_DATA_UTF8, name, name_size, value, value_size));
		}
	}

	return sinfo;
}

static pgp_stream_t *spgp_detach_sign_file(pgp_key_packet **keys, pgp_user_info **uinfos, uint32_t count, void *file)
{
	pgp_stream_t *stream = pgp_stream_new(count);
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_sign_info *sinfo = NULL;

	if (stream == NULL)
	{
		printf("No memory");
		exit(1);
	}

	literal = spgp_read_file_as_literal(file, PGP_LITERAL_DATA_BINARY);

	for (uint32_t i = 0; i < count; ++i)
	{
		sign = NULL;
		sinfo = NULL;

		// Detached signatures are always binary
		sinfo = spgp_create_sign_info(keys[i], uinfos[i], PGP_BINARY_SIGNATURE);
		PGP_CALL(pgp_generate_document_signature(&sign, keys[i], PGP_SIGNATURE_FLAG_DETACHED, sinfo, literal));

		pgp_stream_push(stream, sign);
		pgp_sign_info_delete(sinfo);
	}

	pgp_literal_packet_delete(literal);

	return stream;
}

static pgp_stream_t *spgp_clear_sign_file(pgp_key_packet **keys, pgp_user_info **uinfos, uint32_t count, void *file)
{
	pgp_stream_t *stream = pgp_stream_new(count);
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_sign_info *sinfo = NULL;

	if (stream == NULL)
	{
		printf("No memory");
		exit(1);
	}

	// TODO (Write the data as cleartext)

	literal = spgp_read_file_as_literal(file, PGP_LITERAL_DATA_TEXT);

	for (uint32_t i = 0; i < count; ++i)
	{
		sign = NULL;
		sinfo = NULL;

		// Cleartext signatures are always text
		sinfo = spgp_create_sign_info(keys[i], uinfos[i], PGP_TEXT_SIGNATURE);
		PGP_CALL(pgp_generate_document_signature(&sign, keys[i], PGP_SIGNATURE_FLAG_CLEARTEXT, sinfo, literal));

		pgp_stream_push(stream, sign);
		pgp_sign_info_delete(sinfo);
	}

	pgp_literal_packet_delete(literal);

	return stream;
}

static pgp_stream_t *spgp_sign_file(pgp_key_packet **keys, pgp_user_info **uinfos, uint32_t count, void *file)
{
	pgp_stream_t *stream = pgp_stream_new((count * 2) + 1);
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_one_pass_signature_packet *ops = NULL;
	pgp_sign_info *sinfo[16] = {0};

	pgp_one_pass_signature_version ops_version = (keys[0]->version == PGP_KEY_V6) ? PGP_ONE_PASS_SIGNATURE_V6 : PGP_ONE_PASS_SIGNATURE_V3;
	pgp_signature_type sig_type = command.textmode ? PGP_TEXT_SIGNATURE : PGP_BINARY_SIGNATURE;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = 0;

	if (stream == NULL)
	{
		printf("No memory");
		exit(1);
	}

	// Generate one pass signatures (last to first)
	for (uint32_t i = 0; i < count; ++i)
	{
		byte_t j = count - (i + 1);

		ops = NULL;

		fingerprint_size = pgp_key_fingerprint(keys[j], fingerprint, fingerprint_size);
		sinfo[j] = spgp_create_sign_info(keys[j], uinfos[j], sig_type);

		// Only the last one pass packet will have the nested flag set.
		PGP_CALL(pgp_one_pass_signature_packet_new(&ops, ops_version, sig_type, (j == 0) ? 1 : 0, keys[j]->public_key_algorithm_id,
												   sinfo[j]->hash_algorithm, sinfo[j]->salt, sinfo[j]->salt_size, fingerprint,
												   fingerprint_size));

		pgp_stream_push(stream, ops);
	}

	// Push the literal packet
	literal = spgp_read_file_as_literal(file, command.textmode ? PGP_LITERAL_DATA_TEXT : PGP_LITERAL_DATA_BINARY);
	pgp_stream_push(stream, literal);

	// Generate the signatures (first to last)
	for (uint32_t i = 0; i < count; ++i)
	{
		sign = NULL;

		PGP_CALL(pgp_generate_document_signature(&sign, keys[i], 0, sinfo[i], literal));
		pgp_stream_push(stream, sign);
	}

	// Free sign_infos
	for (uint32_t i = 0; i < count; ++i)
	{
		pgp_sign_info_delete(sinfo[i]);
	}

	return stream;
}

static pgp_stream_t *spgp_sign_file_legacy(pgp_key_packet **keys, pgp_user_info **uinfos, uint32_t count, void *file)
{
	pgp_stream_t *stream = pgp_stream_new(count + 1);
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_sign_info *sinfo = NULL;

	pgp_signature_type sig_type = command.textmode ? PGP_TEXT_SIGNATURE : PGP_BINARY_SIGNATURE;

	if (stream == NULL)
	{
		printf("No memory");
		exit(1);
	}

	// Generate the signatures (first to last)
	for (uint32_t i = 0; i < count; ++i)
	{
		sign = NULL;
		sinfo = NULL;

		sinfo = spgp_create_sign_info(keys[i], uinfos[i], sig_type);
		PGP_CALL(pgp_generate_document_signature(&sign, keys[i], 0, sinfo, literal));

		pgp_stream_push(stream, sign);
		pgp_sign_info_delete(sinfo);
	}

	// Push the literal packet
	literal = spgp_read_file_as_literal(file, command.textmode ? PGP_LITERAL_DATA_TEXT : PGP_LITERAL_DATA_BINARY);
	pgp_stream_push(stream, literal);

	return stream;
}

void spgp_sign(void)
{
	pgp_key_packet *key[16] = {0};
	pgp_user_info *uinfo[16] = {0};
	pgp_keyring_packet *keyring[16] = {0};

	pgp_compresed_packet *compressed = NULL;
	pgp_stream_t *signatures = NULL;
	uint32_t count = 0;

	armor_options options = {0};
	armor_marker marker = {0};
	armor_options *opts = NULL;

	if (command.users == NULL)
	{
		printf("No user specified\n.");
		exit(1);
	}

	count = command.users->count;

	// Search the keyring to find the keys
	for (uint32_t i = 0; i < count; ++i)
	{
		keyring[i] =
			spgp_search_keyring(&key[i], &uinfo[i], command.users->packets[i], strlen(command.users->packets[i]), PGP_KEY_FLAG_SIGN);

		if (keyring[i] == NULL)
		{
			printf("Unable to find user %s\n.", (char *)command.users->packets[i]);
			exit(1);
		}

		if (key[i] == NULL)
		{
			printf("No Signing key for user %s\n.", (char *)command.users->packets[i]);
			exit(1);
		}
	}

	// Decrypt the keys
	for (uint32_t i = 0; i < count; ++i)
	{
		key[i] = spgp_decrypt_key(keyring[i], key[i]);
	}

	// Create the signature
	if (command.files == NULL)
	{
		if (command.detach_sign)
		{
			signatures = spgp_detach_sign_file(key, uinfo, count, NULL);
		}
		if (command.clear_sign)
		{
			signatures = spgp_clear_sign_file(key, uinfo, count, NULL);
		}
		if (command.sign)
		{
			signatures = spgp_sign_file(key, uinfo, count, NULL);
		}
		if (command.legacy_sign)
		{
			signatures = spgp_sign_file_legacy(key, uinfo, count, NULL);
		}
	}
	else
	{
		for (uint32_t i = 0; i < count; ++i)
		{
			if (command.detach_sign)
			{
				signatures = spgp_detach_sign_file(key, uinfo, count, command.files->packets[i]);
			}
			if (command.clear_sign)
			{
				signatures = spgp_clear_sign_file(key, uinfo, count, command.files->packets[i]);
			}
			if (command.sign)
			{
				signatures = spgp_sign_file(key, uinfo, count, command.files->packets[i]);
			}
			if (command.legacy_sign)
			{
				signatures = spgp_sign_file_legacy(key, uinfo, count, command.files->packets[i]);
			}
		}
	}

	// Compress the stream
	if (command.compression_level != 0)
	{
		PGP_CALL(pgp_compressed_packet_new(&compressed, PGP_HEADER, PGP_ZLIB));
		PGP_CALL(pgp_compressed_packet_compress(compressed, signatures));

		signatures = pgp_stream_clear(signatures, pgp_packet_delete);
		signatures = pgp_stream_push(signatures, compressed);
	}

	// Write output
	if (command.armor)
	{
		marker = (armor_marker){.header_line = PGP_ARMOR_BEGIN_SIGNATURE,
								.header_line_size = strlen(PGP_ARMOR_BEGIN_SIGNATURE),
								.trailer_line = PGP_ARMOR_END_SIGNATURE,
								.trailer_line_size = strlen(PGP_ARMOR_END_SIGNATURE)};

		options.marker = &marker;
		options.flags = ARMOR_EMPTY_LINE | ARMOR_CRLF_ENDING | ((command.mode == SPGP_MODE_OPENPGP) ? 0 : ARMOR_CHECKSUM_CRC24);

		opts = &options;
	}

	spgp_write_pgp_packets(signatures, opts, command.output);

	exit(0);
}

uint32_t spgp_verify(spgp_command *command)
{
	void *buffer = NULL;
	size_t size = 0;

	pgp_key_packet *key = NULL;
	pgp_signature_packet *sign = NULL;

	if (command->files == NULL || command->files->count != 2)
	{
		printf("Bad usage.\n");
		exit(1);
	}

	sign = spgp_read_pgp_packet(command->files->packets[0], SPGP_STD_INPUT);
	buffer = spgp_read_file(command->files->packets[1], 0, &size);

	if (sign->hashed_subpackets != NULL)
	{
		for (uint32_t i = 0; i < sign->hashed_subpackets->count; ++i)
		{
			pgp_subpacket_header *header = sign->hashed_subpackets->packets[i];
			pgp_signature_subpacket_type type = header->tag & PGP_SUBPACKET_TAG_MASK;

			if (type == PGP_ISSUER_FINGERPRINT_SUBPACKET)
			{
				pgp_issuer_fingerprint_subpacket *subpacket = sign->hashed_subpackets->packets[i];

				key = spgp_read_key(subpacket->fingerprint, subpacket->header.body_size - 1);
				break;
			}
		}
	}

	if (key == NULL)
	{
		printf("No key found.\n");
		exit(1);
	}

	// uint32_t result = pgp_signature_packet_verify(sign, key, buffer, size);

	// printf("%s\n", result == 1 ? "Good Signature" : "Bad Signature");

	free(buffer);

	return 0;
}
