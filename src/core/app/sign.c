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

static uint32_t spgp_get_sign_fingerprint(pgp_signature_packet *sign, byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE])
{
	if (sign->hashed_subpackets != NULL)
	{
		for (uint32_t i = 0; i < sign->hashed_subpackets->count; ++i)
		{
			pgp_subpacket_header *header = sign->hashed_subpackets->packets[i];
			pgp_signature_subpacket_type type = header->tag & PGP_SUBPACKET_TAG_MASK;

			if (type == PGP_ISSUER_FINGERPRINT_SUBPACKET)
			{
				pgp_issuer_fingerprint_subpacket *subpacket = sign->hashed_subpackets->packets[i];

				memcpy(fingerprint, subpacket->fingerprint, subpacket->header.body_size - 1);
				return subpacket->header.body_size - 1;
			}

			if (type == PGP_ISSUER_KEY_ID_SUBPACKET)
			{
				pgp_issuer_key_id_subpacket *subpacket = sign->hashed_subpackets->packets[i];

				memcpy(fingerprint, subpacket->key_id, PGP_KEY_ID_SIZE);
				return PGP_KEY_ID_SIZE;
			}
		}
	}

	if (sign->unhashed_subpackets != NULL)
	{
		for (uint32_t i = 0; i < sign->unhashed_subpackets->count; ++i)
		{
			pgp_subpacket_header *header = sign->unhashed_subpackets->packets[i];
			pgp_signature_subpacket_type type = header->tag & PGP_SUBPACKET_TAG_MASK;

			if (type == PGP_ISSUER_FINGERPRINT_SUBPACKET)
			{
				pgp_issuer_fingerprint_subpacket *subpacket = sign->unhashed_subpackets->packets[i];

				memcpy(fingerprint, subpacket->fingerprint, subpacket->header.body_size - 1);
				return subpacket->header.body_size - 1;
			}

			if (type == PGP_ISSUER_KEY_ID_SUBPACKET)
			{
				pgp_issuer_key_id_subpacket *subpacket = sign->unhashed_subpackets->packets[i];

				memcpy(fingerprint, subpacket->key_id, PGP_KEY_ID_SIZE);
				return PGP_KEY_ID_SIZE;
			}
		}
	}

	return 0;
}

static pgp_sign_info *spgp_create_sign_info(pgp_key_packet *key, pgp_user_info *uinfo, pgp_signature_type type)
{
	pgp_sign_info *sinfo = NULL;
	pgp_hash_algorithms algorithm = preferred_hash_algorithm_for_signature(key);

	// Create the structure
	PGP_CALL(pgp_sign_info_new(&sinfo, type, algorithm, 0, 0, 0, 0));

	// Set the signer
	PGP_CALL(pgp_sign_info_set_signer_id(sinfo, uinfo->uid, uinfo->uid_octets));

	// Generate salt
	if (key->version == PGP_KEY_V6)
	{
		PGP_CALL(pgp_rand(sinfo->salt, (sinfo->salt_size = 32)));
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
	pgp_stream_t *stream = NULL;
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_sign_info *sinfo = NULL;

	STREAM_CALL(stream = pgp_stream_new(count));
	literal = spgp_literal_read_file(file, PGP_LITERAL_DATA_BINARY);

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

static uint32_t spgp_detach_verify_stream(pgp_stream_t *stream, void *file)
{
	pgp_error_t status = 0;

	pgp_signature_packet *sign = NULL;
	pgp_key_packet *key = NULL;
	pgp_user_info *uinfo = NULL;

	pgp_literal_packet *literal = NULL;
	pgp_literal_packet *literal_binary = NULL;
	pgp_literal_packet *literal_text = NULL;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = 0;

	pgp_literal_data_format format = 0;
	byte_t changing_format = 0;

	sign = stream->packets[0];
	format = (sign->type == PGP_BINARY_SIGNATURE) ? PGP_LITERAL_DATA_BINARY : PGP_LITERAL_DATA_TEXT;

	for (uint32_t i = 1; i < stream->count; ++i)
	{
		sign = stream->packets[i];

		if (format != ((sign->type == PGP_BINARY_SIGNATURE) ? PGP_LITERAL_DATA_BINARY : PGP_LITERAL_DATA_TEXT))
		{
			changing_format = 1;

			literal_binary = spgp_literal_read_file(file, PGP_LITERAL_DATA_BINARY);
			literal_text = spgp_literal_read_file(file, PGP_LITERAL_DATA_TEXT);

			break;
		}
	}

	if (changing_format == 0)
	{
		literal = (format == PGP_BINARY_SIGNATURE) ? literal_binary : literal_text;
	}

	for (uint32_t i = 1; i < stream->count; ++i)
	{
		sign = stream->packets[i];
		key = NULL;
		uinfo = NULL;

		fingerprint_size = spgp_get_sign_fingerprint(sign, fingerprint);

		if (fingerprint_size != 0)
		{
			spgp_search_keyring(&key, &uinfo, fingerprint, fingerprint_size, PGP_KEY_FLAG_SIGN);
		}

		if (key != NULL)
		{
			if (changing_format == 0)
			{
				status = pgp_verify_document_signature(sign, key, literal);
			}
			else
			{
				status = pgp_verify_document_signature(sign, key, (sign->type == PGP_BINARY_SIGNATURE) ? literal_binary : literal_text);
			}
		}
	}

	pgp_literal_packet_delete(literal_binary);
	pgp_literal_packet_delete(literal_text);

	return status;
}

static pgp_stream_t *spgp_clear_sign_file(pgp_key_packet **keys, pgp_user_info **uinfos, uint32_t count, void *file)
{
	pgp_stream_t *stream = NULL;
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_sign_info *sinfo = NULL;

	STREAM_CALL(stream = pgp_stream_new(count));

	// TODO (Write the data as cleartext)
	literal = spgp_literal_read_file(file, PGP_LITERAL_DATA_TEXT);

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
	pgp_stream_t *stream = NULL;
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_one_pass_signature_packet *ops = NULL;
	pgp_sign_info *sinfo[16] = {0};

	pgp_one_pass_signature_version ops_version = (keys[0]->version == PGP_KEY_V6) ? PGP_ONE_PASS_SIGNATURE_V6 : PGP_ONE_PASS_SIGNATURE_V3;
	pgp_signature_type sig_type = command.textmode ? PGP_TEXT_SIGNATURE : PGP_BINARY_SIGNATURE;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	STREAM_CALL(stream = pgp_stream_new((count * 2) + 1));

	// Generate one pass signatures (last to first)
	for (uint32_t i = 0; i < count; ++i)
	{
		byte_t j = count - (i + 1);

		ops = NULL;

		PGP_CALL(pgp_key_fingerprint(keys[j], fingerprint, &fingerprint_size));
		sinfo[j] = spgp_create_sign_info(keys[j], uinfos[j], sig_type);

		// Only the last one pass packet will have the nested flag set.
		PGP_CALL(pgp_one_pass_signature_packet_new(&ops, ops_version, sig_type, (j == 0) ? 1 : 0, keys[j]->public_key_algorithm_id,
												   sinfo[j]->hash_algorithm, sinfo[j]->salt, sinfo[j]->salt_size, fingerprint,
												   fingerprint_size));

		pgp_stream_push(stream, ops);
	}

	// Push the literal packet
	literal = spgp_literal_read_file(file, command.textmode ? PGP_LITERAL_DATA_TEXT : PGP_LITERAL_DATA_BINARY);
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

static uint32_t spgp_verify_stream(pgp_stream_t *stream)
{
	pgp_error_t status = 0;

	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_one_pass_signature_packet *ops = NULL;

	pgp_key_packet *key = NULL;
	pgp_user_info *uinfo = NULL;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = 0;

	uint32_t count = (stream->count - 1) / 2;

	literal = stream->packets[count];

	for (uint32_t i = 0; i < count; ++i)
	{
		ops = stream->packets[i];
		sign = stream->packets[stream->count - 1 - i];

		if (ops->type != sign->type)
		{
			printf("Signature type mismatch.\n");
			exit(1);
		}

		fingerprint_size = spgp_get_sign_fingerprint(sign, fingerprint);

		if (fingerprint_size != 0)
		{
			spgp_search_keyring(&key, &uinfo, fingerprint, fingerprint_size, PGP_KEY_FLAG_SIGN);
		}

		if (key != NULL)
		{
			status = pgp_verify_document_signature(sign, key, literal);
		}
	}

	return status;
}

static pgp_stream_t *spgp_sign_file_legacy(pgp_key_packet **keys, pgp_user_info **uinfos, uint32_t count, void *file)
{
	pgp_stream_t *stream = NULL;
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_sign_info *sinfo = NULL;

	pgp_signature_type sig_type = command.textmode ? PGP_TEXT_SIGNATURE : PGP_BINARY_SIGNATURE;

	STREAM_CALL(stream = pgp_stream_new(count + 1));

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
	literal = spgp_literal_read_file(file, command.textmode ? PGP_LITERAL_DATA_TEXT : PGP_LITERAL_DATA_BINARY);
	pgp_stream_push(stream, literal);

	return stream;
}

static uint32_t spgp_verify_stream_legacy(pgp_stream_t *stream)
{
	pgp_error_t status = 0;

	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;

	pgp_key_packet *key = NULL;
	pgp_user_info *uinfo = NULL;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = 0;

	uint32_t count = (stream->count - 1);

	literal = stream->packets[count];

	for (uint32_t i = 0; i < count; ++i)
	{
		sign = stream->packets[i];

		fingerprint_size = spgp_get_sign_fingerprint(sign, fingerprint);

		if (fingerprint_size != 0)
		{
			spgp_search_keyring(&key, &uinfo, fingerprint, fingerprint_size, PGP_KEY_FLAG_SIGN);
		}

		if (key != NULL)
		{
			status = pgp_verify_document_signature(sign, key, literal);
		}
	}

	return status;
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
	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		if (command.detach_sign)
		{
			signatures = spgp_detach_sign_file(key, uinfo, count, command.args->packets[i]);
		}
		if (command.clear_sign)
		{
			signatures = spgp_clear_sign_file(key, uinfo, count, command.args->packets[i]);
		}
		if (command.sign)
		{
			if (command.mode != SPGP_MODE_RFC2440)
			{
				signatures = spgp_sign_file(key, uinfo, count, command.args->packets[i]);
			}
			else
			{
				signatures = spgp_sign_file_legacy(key, uinfo, count, command.args->packets[i]);
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

	spgp_write_pgp_packets(command.output, signatures, opts);
}

static uint32_t spgp_verify_file(void *file)
{
	pgp_stream_t *stream = NULL;
	pgp_packet_header *header = NULL;
	pgp_packet_type type = 0;

	stream = spgp_read_pgp_packets(file);
	stream = pgp_packet_stream_filter_padding_packets(stream);

	// Check signature types
	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_SIG)
		{
			pgp_signature_packet *sign = stream->packets[i];

			if (sign->type != PGP_BINARY_SIGNATURE && sign->type != PGP_TEXT_SIGNATURE)
			{
				printf("Not a document signature.\n");
				exit(1);
			}
		}

		if (type == PGP_OPS)
		{
			pgp_one_pass_signature_packet *ops = stream->packets[i];

			if (ops->type != PGP_BINARY_SIGNATURE && ops->type != PGP_TEXT_SIGNATURE)
			{
				printf("Not a document signature.\n");
				exit(1);
			}
		}
	}

	header = stream->packets[0];
	type = pgp_packet_type_from_tag(header->tag);

	// Check packet sequence
	if (type == PGP_OPS)
	{
		if ((stream->count - 1) % 2 != 0)
		{
			printf("Bad Signature Sequence.\n");
			exit(1);
		}

		for (uint32_t i = 1; i < stream->count; ++i)
		{
			header = stream->packets[i];
			type = pgp_packet_type_from_tag(header->tag);

			if (i < (stream->count - 1) / 2)
			{
				if (type != PGP_OPS)
				{
					printf("Bad Signature Sequence.\n");
					exit(1);
				}
			}
			else if (i > (stream->count - 1) / 2)
			{
				if (type != PGP_SIG)
				{
					printf("Bad Signature Sequence.\n");
					exit(1);
				}
			}
			else // (i == (stream->count - 1) / 2)
			{
				if (type != PGP_LIT)
				{
					printf("Bad Signature Sequence.\n");
					exit(1);
				}
			}
		}

		return spgp_verify_stream(stream);
	}

	if (type == PGP_SIG)
	{
		for (uint32_t i = 1; i < stream->count; ++i)
		{
			header = stream->packets[i];
			type = pgp_packet_type_from_tag(header->tag);

			if (i != stream->count - 1)
			{
				if (type != PGP_SIG)
				{
					printf("Bad Signature Sequence.\n");
					exit(1);
				}
			}
			else
			{
				if (type == PGP_SIG)
				{
					return spgp_detach_verify_stream(stream, command.args->packets[1]);
				}

				if (type == PGP_LIT)
				{
					return spgp_verify_stream_legacy(stream);
				}

				printf("Bad Signature Sequence.\n");
				exit(1);
			}
		}
	}

	// Unreachable
	return 0;
}

void spgp_verify(void)
{
	uint32_t status = 0;

	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		status += spgp_verify_file(command.args->packets[i]);
	}

	if (status != 0)
	{
		exit(1);
	}
}
