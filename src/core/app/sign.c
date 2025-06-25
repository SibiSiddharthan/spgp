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

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

static size_t print_fingerprint(byte_t *fingerprint, byte_t size, char *out)
{
	byte_t pos = 0;

	for (uint32_t i = 0; i < size; ++i)
	{
		byte_t a, b;

		a = fingerprint[i] / 16;
		b = fingerprint[i] % 16;

		out[pos++] = hex_table[a];
		out[pos++] = hex_table[b];
	}

	return pos;
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

	// Git gpg interface compatibility
	if (command.status_fd != 0)
	{
		handle_t handle = command.status_fd == 1 ? STDOUT_HANDLE : STDERR_HANDLE;

		char gpg_buffer[256] = {0};
		char fingerprint[128] = {0};
		byte_t gpg_pos = 0;

		size_t result = 0;

		print_fingerprint(keys[0]->fingerprint, keys[0]->fingerprint_size, fingerprint);

		gpg_pos += snprintf(gpg_buffer + gpg_pos, 256 - gpg_pos, "[GNUPG:] KEY_CONSIDERED %s\n", fingerprint);
		gpg_pos += snprintf(gpg_buffer + gpg_pos, 256 - gpg_pos, "[GNUPG:] SIG_CREATED USING %s\n", fingerprint);

		OS_CALL(os_write(handle, gpg_buffer, gpg_pos, &result), printf("Unable to write to handle %u", OS_HANDLE_AS_UINT(handle)));
	}

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

	// Read the file
	if (sign->type == PGP_BINARY_SIGNATURE)
	{
		literal_binary = spgp_literal_read_file(file, PGP_LITERAL_DATA_BINARY);
	}
	else
	{
		literal_text = spgp_literal_read_file(file, PGP_LITERAL_DATA_TEXT);
	}

	for (uint32_t i = 1; i < stream->count; ++i)
	{
		sign = stream->packets[i];

		if (format != ((sign->type == PGP_BINARY_SIGNATURE) ? PGP_LITERAL_DATA_BINARY : PGP_LITERAL_DATA_TEXT))
		{
			changing_format = 1;

			if (sign->type == PGP_BINARY_SIGNATURE)
			{
				literal_binary = spgp_literal_read_file(file, PGP_LITERAL_DATA_BINARY);
			}
			else
			{
				literal_text = spgp_literal_read_file(file, PGP_LITERAL_DATA_TEXT);
			}

			break;
		}
	}

	if (changing_format == 0)
	{
		literal = (format == PGP_LITERAL_DATA_BINARY) ? literal_binary : literal_text;
	}

	// For V5 detached document signature metadata
	if (literal_binary != NULL)
	{
		literal_binary->format = 0;
		literal_binary->filename_size = 0;
		literal_binary->date = 0;
	}

	if (literal_text != NULL)
	{
		literal_text->format = 0;
		literal_text->filename_size = 0;
		literal_text->date = 0;
	}

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		sign = stream->packets[i];
		key = NULL;
		uinfo = NULL;

		fingerprint_size = spgp_get_sign_fingerprint(sign, fingerprint);

		if (fingerprint_size != 0)
		{
			spgp_search_keyring(&key, &uinfo, fingerprint, fingerprint_size, PGP_KEY_FLAG_SIGN);
		}

		if (key == NULL)
		{
			printf("No public key to verify signature.\n");
			exit(1);
		}

		if (changing_format == 0)
		{
			status = spgp_verify_signature(sign, key, NULL, uinfo, literal, 1);
		}
		else
		{
			status = spgp_verify_signature(sign, key, NULL, uinfo, (sign->type == PGP_BINARY_SIGNATURE) ? literal_binary : literal_text, 1);
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

static uint32_t spgp_clear_verify_stream(pgp_stream_t *stream)
{
	pgp_error_t status = 0;

	pgp_signature_packet *sign = NULL;
	pgp_key_packet *key = NULL;
	pgp_user_info *uinfo = NULL;

	pgp_literal_packet *literal = stream->packets[0];

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = 0;

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

		if (key == NULL)
		{
			printf("No public key to verify signature.\n");
			exit(1);
		}

		status = spgp_verify_signature(sign, key, NULL, uinfo, literal, 1);
	}

	return status;
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

	byte_t key_id[PGP_KEY_ID_SIZE] = {0};

	void *in = NULL;
	byte_t in_size = 0;

	STREAM_CALL(stream = pgp_stream_new((count * 2) + 1));

	// Generate one pass signatures (last to first)
	for (uint32_t i = 0; i < count; ++i)
	{
		byte_t j = count - (i + 1);

		ops = NULL;

		PGP_CALL(pgp_key_fingerprint(keys[j], fingerprint, &fingerprint_size));
		sinfo[j] = spgp_create_sign_info(keys[j], uinfos[j], sig_type);

		if (ops_version == PGP_ONE_PASS_SIGNATURE_V3)
		{
			pgp_key_id_from_fingerprint(keys[j]->version, key_id, fingerprint, fingerprint_size);

			in = key_id;
			in_size = PGP_KEY_ID_SIZE;
		}
		else
		{
			in = fingerprint;
			in_size = fingerprint_size;
		}

		// Only the last one pass packet will have the nested flag set.
		PGP_CALL(pgp_one_pass_signature_packet_new(&ops, ops_version, sig_type, (j == 0) ? 1 : 0, keys[j]->public_key_algorithm_id,
												   sinfo[j]->hash_algorithm, sinfo[j]->salt, sinfo[j]->salt_size, in, in_size));

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

		if (key == NULL)
		{
			printf("No public key to verify signature.\n");
			exit(1);
		}

		status = spgp_verify_signature(sign, key, NULL, uinfo, literal, 1);
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

		if (key == NULL)
		{
			printf("No public key to verify signature.\n");
			exit(1);
		}

		status = spgp_verify_signature(sign, key, NULL, uinfo, literal, 1);
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
		keyring[i] = spgp_search_keyring(&key[i], &uinfo[i], command.users->data[i], strlen(command.users->data[i]), PGP_KEY_FLAG_SIGN);

		if (keyring[i] == NULL)
		{
			printf("Unable to find user %s\n.", (char *)command.users->data[i]);
			exit(1);
		}

		if (key[i] == NULL)
		{
			printf("No Signing key for user %s\n.", (char *)command.users->data[i]);
			exit(1);
		}
	}

	// Decrypt the keys
	for (uint32_t i = 0; i < count; ++i)
	{
		key[i] = spgp_decrypt_key(keyring[i], key[i]);
	}

	// Armor setup
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

	// Create the signature
	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		if (command.detach_sign)
		{
			signatures = spgp_detach_sign_file(key, uinfo, count, command.args->data[i]);
		}
		else if (command.clear_sign)
		{
			signatures = spgp_clear_sign_file(key, uinfo, count, command.args->data[i]);
		}
		else // (command.sign)
		{
			if (command.mode != SPGP_MODE_RFC2440)
			{
				signatures = spgp_sign_file(key, uinfo, count, command.args->data[i]);
			}
			else
			{
				signatures = spgp_sign_file_legacy(key, uinfo, count, command.args->data[i]);
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
		spgp_write_pgp_packets(command.output, signatures, opts);
	}
}

static uint32_t spgp_verify_file(void *file, uint32_t index)
{
	pgp_stream_t *stream = NULL;
	pgp_packet_header *header = NULL;
	pgp_packet_type type = 0;

	stream = spgp_read_pgp_packets(file);
	stream = spgp_preprocess_stream(stream);

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
		}

		header = stream->packets[stream->count - 1];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_SIG)
		{
			if ((index + 1) == command.args->count)
			{
				printf("Signing data not provided.\n");
				exit(1);
			}

			return spgp_detach_verify_stream(stream, pgp_stream_remove(command.args, index + 1));
		}
		else if (type == PGP_LIT)
		{
			return spgp_verify_stream_legacy(stream);
		}
		else
		{
			printf("Bad Signature Sequence.\n");
			exit(1);
		}
	}

	if (type == PGP_LIT)
	{
		if (stream->count < 2)
		{
			printf("Bad Signature Sequence.\n");
			exit(1);
		}

		for (uint32_t i = 1; i < stream->count; ++i)
		{
			header = stream->packets[i];
			type = pgp_packet_type_from_tag(header->tag);

			if (type != PGP_SIG)
			{
				printf("Bad Signature Sequence.\n");
				exit(1);
			}
		}

		return spgp_clear_verify_stream(stream);
	}

	// Unreachable
	return 0;
}

void spgp_verify(void)
{
	uint32_t status = 0;

	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		status += spgp_verify_file(command.args->data[i], i);
	}

	if (status != 0)
	{
		exit(1);
	}
}

static void print_key(pgp_key_packet *key, char key_buffer[128])
{
	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	char fingerprint_buffer[64] = {0};

	switch (key->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *rsa_key = key->key;
		snprintf(key_buffer, 128, "rsa%u key", ROUND_UP(rsa_key->n->bits, 1024));
		break;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *elgmal_key = key->key;
		snprintf(key_buffer, 128, "elg%u key", ROUND_UP(elgmal_key->p->bits, 1024));
		break;
	}
	case PGP_DSA:
	{
		pgp_dsa_key *dsa_key = key->key;
		snprintf(key_buffer, 128, "dsa%u key", ROUND_UP(dsa_key->p->bits, 1024));
		break;
	}
	case PGP_ECDH:
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		byte_t *curve_id = key->key;
		char *curve = NULL;

		// Only need first byte.
		switch (*curve_id)
		{
		case PGP_EC_NIST_P256:
			curve = "nistp256";
			break;
		case PGP_EC_NIST_P384:
			curve = "nistp384";
			break;
		case PGP_EC_NIST_P521:
			curve = "nistp521";
			break;
		case PGP_EC_BRAINPOOL_256R1:
			curve = "brainpoolP256r1";
			break;
		case PGP_EC_BRAINPOOL_384R1:
			curve = "brainpoolP384r1";
			break;
		case PGP_EC_BRAINPOOL_512R1:
			curve = "brainpoolP512r1";
			break;
		case PGP_EC_ED25519:
			curve = "ed25519";
			break;
		case PGP_EC_ED448:
			curve = "ed448";
			break;

		default:
			curve = "unknown";
			break;
		}

		snprintf(key_buffer, 128, "%s", curve);
		break;
	}
	case PGP_ED25519:
		snprintf(key_buffer, 128, "ed25519");
		break;
	case PGP_ED448:
		snprintf(key_buffer, 128, "ed448");
		break;
	default:
		snprintf(key_buffer, 128, "unknown");
	}

	PGP_CALL(pgp_key_fingerprint(key, fingerprint, &fingerprint_size));
	print_fingerprint(fingerprint, fingerprint_size, fingerprint_buffer);

	strncat(key_buffer, " (", 2);
	strncat(key_buffer, fingerprint_buffer, fingerprint_size * 2);
	strncat(key_buffer, ")", 1);
}

static char *get_trust_value(byte_t trust)
{
	switch (trust)
	{
	case PGP_TRUST_NEVER:
		return "never";
	case PGP_TRUST_REVOKED:
		return "revoked";
	case PGP_TRUST_MARGINAL:
		return "marginal";
	case PGP_TRUST_FULL:
		return "full";
	case PGP_TRUST_ULTIMATE:
		return "ultimate";
	default:
		return "unknown";
	}
}

static void get_signature_times(pgp_signature_packet *sign, time_t *creation_time, time_t *expiry_time)
{
	pgp_subpacket_header *header = NULL;
	pgp_timestamp_subpacket *subpacket = NULL;

	// Search hashed subpackets only
	if (sign->hashed_subpackets == NULL)
	{
		// V3 signatures
		*creation_time = sign->timestamp;
		return;
	}

	for (uint32_t i = 0; i < sign->hashed_subpackets->count; ++i)
	{
		header = sign->hashed_subpackets->packets[i];

		if ((header->tag & PGP_SUBPACKET_TAG_MASK) == PGP_SIGNATURE_CREATION_TIME_SUBPACKET)
		{
			subpacket = sign->hashed_subpackets->packets[i];
			*creation_time = subpacket->timestamp;
		}

		if ((header->tag & PGP_SUBPACKET_TAG_MASK) == PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET)
		{
			subpacket = sign->hashed_subpackets->packets[i];
			*expiry_time = subpacket->duration;
		}
	}

	// The expiry time is given in seconds since creation time
	if (*expiry_time > 0)
	{
		*expiry_time = *expiry_time + *creation_time;
	}
}

static uint32_t get_signature_strings(pgp_signature_packet *sign, pgp_signature_subpacket_type type, char *str, uint32_t size)
{
	pgp_subpacket_header *header = NULL;
	pgp_string_subpacket *subpacket = NULL;

	uint32_t pos = 0;

	// Search hashed first
	if (sign->hashed_subpackets != NULL)
	{
		for (uint32_t i = 0; i < sign->hashed_subpackets->count; ++i)
		{
			header = sign->hashed_subpackets->packets[i];
			subpacket = sign->hashed_subpackets->packets[i];

			if ((header->tag & PGP_SUBPACKET_TAG_MASK) == type)
			{
				switch ((header->tag & PGP_SUBPACKET_TAG_MASK))
				{
				case PGP_SIGNER_USER_ID_SUBPACKET:
					pos += snprintf(str, size - pos, "        Issuer: %.*s\n", (uint32_t)subpacket->header.body_size,
									(char *)subpacket->data); // 8 spaces
					break;
				case PGP_POLICY_URI_SUBPACKET:
					pos += snprintf(str, size - pos, "        Policy: %.*s\n", (uint32_t)subpacket->header.body_size,
									(char *)subpacket->data); // 8 spaces
					break;
				}
			}
		}
	}

	if (sign->unhashed_subpackets != NULL)
	{
		for (uint32_t i = 0; i < sign->unhashed_subpackets->count; ++i)
		{
			header = sign->unhashed_subpackets->packets[i];
			subpacket = sign->unhashed_subpackets->packets[i];

			if ((header->tag & PGP_SUBPACKET_TAG_MASK) == type)
			{
				switch ((header->tag & PGP_SUBPACKET_TAG_MASK))
				{
				case PGP_SIGNER_USER_ID_SUBPACKET:
					pos += snprintf(str, size - pos, "        Issuer: %.*s\n", (uint32_t)subpacket->header.body_size,
									(char *)subpacket->data); // 8 spaces
					break;
				case PGP_POLICY_URI_SUBPACKET:
					pos += snprintf(str, size - pos, "        Policy: %.*s\n", (uint32_t)subpacket->header.body_size,
									(char *)subpacket->data); // 8 spaces
					break;
				}
			}
		}
	}

	return pos;
}

pgp_error_t spgp_verify_signature(pgp_signature_packet *sign, pgp_key_packet *key, pgp_key_packet *tpkey, pgp_user_info *uinfo, void *data,
								  byte_t print)
{
	pgp_error_t status = 0;
	size_t result = 0;

	char time_buffer[128] = {0};
	char key_buffer[128] = {0};
	char *sign_type = NULL;
	char *status_type = NULL;

	char buffer[1024] = {0};
	uint32_t size = 1024;
	uint32_t pos = 0;

	time_t creation_time = 0;
	time_t expiry_time = 0;
	time_t current_time = time(NULL);

	// Validate the signature
	status = pgp_signature_validate(sign);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Verify the signature first
	switch (sign->type)
	{
	case PGP_BINARY_SIGNATURE:
		status = pgp_verify_document_signature(sign, key, data);
		sign_type = "Document Signature";
		break;
	case PGP_TEXT_SIGNATURE:
		status = pgp_verify_document_signature(sign, key, data);
		sign_type = "Document Signature (Text)";
		break;

	case PGP_GENERIC_CERTIFICATION_SIGNATURE:
	case PGP_PERSONA_CERTIFICATION_SIGNATURE:
	case PGP_CASUAL_CERTIFICATION_SIGNATURE:
	case PGP_POSITIVE_CERTIFICATION_SIGNATURE:
		status = pgp_verify_certificate_binding_signature(sign, key, tpkey, data);
		sign_type = "Certification Signature";
		break;
	case PGP_ATTESTED_KEY_SIGNATURE:
		status = pgp_verify_certificate_binding_signature(sign, key, tpkey, data);
		sign_type = "Attestation Signature";
		break;
	case PGP_CERTIFICATION_REVOCATION_SIGNATURE:
		status = pgp_verify_revocation_signature(sign, key, tpkey, data);
		sign_type = "Certficate Revocation Signature";
		break;

	case PGP_SUBKEY_BINDING_SIGNATURE:
	case PGP_PRIMARY_KEY_BINDING_SIGNATURE:
		status = pgp_verify_subkey_binding_signature(sign, key, data);
		sign_type = "Subkey Binding Signature";
		break;
	case PGP_SUBKEY_REVOCATION_SIGNATURE:
	case PGP_KEY_REVOCATION_SIGNATURE:
		status = pgp_verify_revocation_signature(sign, key, tpkey, data);
		sign_type = "Key Revocation Signature";
		break;

	case PGP_DIRECT_KEY_SIGNATURE:
		status = pgp_verify_direct_key_signature(sign, key);
		sign_type = "Direct Key Signature";
		break;

	case PGP_THIRD_PARTY_CONFIRMATION_SIGNATURE:
		status = pgp_verify_confirmation_signature(sign, key, data);
		sign_type = "Third Party Confirmation Signature";
		break;

	case PGP_STANDALONE_SIGNATURE:
		sign_type = "Standalone Signature";
		status = pgp_verify_signature(sign, key, NULL, NULL);
		break;
	case PGP_TIMESTAMP_SIGNATURE:
		sign_type = "Timestamp Signature";
		status = pgp_verify_signature(sign, key, NULL, NULL);
		break;
	}

	// Deduce the correct status
	// Get the signature creation time and expiry time
	get_signature_times(sign, &creation_time, &expiry_time);

	if (status == PGP_SUCCESS)
	{
		// Check if signature is made after key has been revoked
		if (key->key_revocation_time > (uint32_t)creation_time)
		{
			status_type = "Good Signature (Revoked Key)";
			status = PGP_BAD_SIGNATURE;
		}
		// Check if signature is made after key has expired
		else if (key->key_expiry_seconds != 0 && creation_time > (key->key_creation_time + key->key_expiry_seconds))
		{
			status_type = "Good Signature (Expired Key)";
			status = PGP_BAD_SIGNATURE;
		}
		else if (expiry_time != 0 && current_time > expiry_time)
		{
			status_type = "Good Signature (Expired)";
			status = PGP_BAD_SIGNATURE;
		}
		else
		{
			status_type = "Good Signature";
		}
	}
	else
	{
		status_type = "Bad Signature";
	}

	if (print == 0)
	{
		return status;
	}

	// For the print message
	// [Signature Type] Made On [Time] Using [Key]
	// [Optional Attributes]
	// [Status] [UID]

	// Signature type
	pos += snprintf(buffer + pos, size - pos, "%s ", sign_type);

	// Time
	strftime(time_buffer, 128, "%Y-%m-%d %H:%M:%S", localtime(&creation_time));
	pos += snprintf(buffer + pos, size - pos, "Made On %s ", time_buffer);

	// Key
	print_key(key, key_buffer);
	pos += snprintf(buffer + pos, size - pos, "Using %s\n", key_buffer);

	// Attuributes
	// Expiry time
	if (expiry_time > 0)
	{
		memset(time_buffer, 0, 128);
		strftime(time_buffer, 128, "%Y-%m-%d %H:%M:%S", localtime(&creation_time));
		pos += snprintf(buffer + pos, size - pos, "        Expiry: %s\n", time_buffer); // 8 spaces
	}

	// Issuer
	pos += get_signature_strings(sign, PGP_SIGNER_USER_ID_SUBPACKET, buffer + pos, size - pos);

	// Policy
	pos += get_signature_strings(sign, PGP_POLICY_URI_SUBPACKET, buffer + pos, size - pos);

	// Status
	pos += snprintf(buffer + pos, size - pos, "%s ", status_type);

	if (uinfo != NULL)
	{
		pos += snprintf(buffer + pos, size - pos, "from \"%.*s\" ", uinfo->uid_octets, (char *)uinfo->uid);
		pos += snprintf(buffer + pos, size - pos, "[%s]\n", get_trust_value(uinfo->trust));
	}
	else
	{
		pos += snprintf(buffer + pos, size - pos, "\n");
	}

	// Write status to stderr
	OS_CALL(os_write(STDERR_HANDLE, buffer, pos, &result), printf("Unable to write to handle %u", OS_HANDLE_AS_UINT(STDERR_HANDLE)));

	// Git gpg interface compatibility
	if (command.status_fd != 0)
	{
		handle_t handle = command.status_fd == 1 ? STDOUT_HANDLE : STDERR_HANDLE;

		char gpg_buffer[256] = {0};
		char fingerprint[128] = {0};
		byte_t gpg_pos = 0;

		print_fingerprint(key->fingerprint, key->fingerprint_size, fingerprint);

		gpg_pos += snprintf(gpg_buffer + gpg_pos, 256 - gpg_pos, "[GNUPG:] KEY_CONSIDERED %s\n", fingerprint);
		gpg_pos +=
			snprintf(gpg_buffer + gpg_pos, 256 - gpg_pos, "[GNUPG:] %s %s\n", (status == PGP_SUCCESS) ? "GOODSIG" : "BADSIG", fingerprint);

		OS_CALL(os_write(handle, gpg_buffer, gpg_pos, &result), printf("Unable to write to handle %u", OS_HANDLE_AS_UINT(handle)));
	}

	return status;
}
