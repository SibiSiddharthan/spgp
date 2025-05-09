/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <key.h>
#include <signature.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pgp_stream_t *spgp_detach_sign_file(pgp_key_packet **keys, pgp_user_info **uinfos, uint32_t count, void *file)
{
	pgp_stream_t *stream = pgp_stream_new(count);
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;

	if (stream == NULL)
	{
		printf("No memory");
		exit(1);
	}

	literal = spgp_read_file_as_literal(file, PGP_LITERAL_DATA_BINARY);

	for (uint32_t i = 0; i < count; ++i)
	{
		sign = NULL;

		PGP_CALL(pgp_generate_document_signature(&sign, keys[i], PGP_SIGNATURE_FLAG_DETACHED, NULL, literal));
		pgp_stream_push(stream, sign);
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

	pgp_one_pass_signature_version ops_version = PGP_ONE_PASS_SIGNATURE_V3;
	pgp_signature_type sig_type = PGP_BINARY_SIGNATURE;

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

		PGP_CALL(pgp_one_pass_signature_packet_new(&ops, ops_version, sig_type, 0, keys[j]->public_key_algorithm_id, 0, NULL, 0,
												   fingerprint, fingerprint_size));
		pgp_stream_push(stream, ops);
	}

	// Push the literal packet
	literal = spgp_read_file_as_literal(file, PGP_LITERAL_DATA_BINARY);
	pgp_stream_push(stream, literal);

	// Generate the signatures (first to last)
	for (uint32_t i = 0; i < count; ++i)
	{
		sign = NULL;

		PGP_CALL(pgp_generate_document_signature(&sign, keys[i], 0, NULL, literal));
		pgp_stream_push(stream, sign);
	}

	return stream;
}

static pgp_stream_t *spgp_sign_file_legacy(pgp_key_packet **keys, pgp_user_info **uinfos, uint32_t count, void *file)
{
	pgp_stream_t *stream = pgp_stream_new(count + 1);
	pgp_literal_packet *literal = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_one_pass_signature_packet *ops = NULL;

	if (stream == NULL)
	{
		printf("No memory");
		exit(1);
	}

	// Generate the signatures (first to last)
	for (uint32_t i = 0; i < count; ++i)
	{
		sign = NULL;

		PGP_CALL(pgp_generate_document_signature(&sign, keys[i], 0, NULL, literal));
		pgp_stream_push(stream, sign);
	}

	// Push the literal packet
	literal = spgp_read_file_as_literal(file, PGP_LITERAL_DATA_BINARY);
	pgp_stream_push(stream, literal);

	return stream;
}

void spgp_sign(void)
{
	void *buffer = NULL;
	void *file = NULL;
	size_t size = 0;

	pgp_key_packet *key[16] = {0};
	pgp_user_info *uinfo[16] = {0};
	pgp_keyring_packet *keyring[16] = {0};

	pgp_stream_t *signatures = NULL;

	uint32_t count = 0;

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

	if (command.files == NULL)
	{
		signatures = spgp_detach_sign_file(key, uinfo, count, NULL);
	}
	else
	{
		for (uint32_t i = 0; i < count; ++i)
		{
			signatures = spgp_detach_sign_file(key, uinfo, count, command.files->packets[i]);
		}
	}

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
