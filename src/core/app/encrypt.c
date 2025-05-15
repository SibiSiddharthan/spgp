/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <key.h>
#include <crypto.h>
#include <session.h>
#include <seipd.h>
#include <signature.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pgp_stream_t *spgp_sign_mdc(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
								   void *file)
{
}

void spgp_encrypt()
{
	pgp_key_packet *key[16] = {0};
	pgp_user_info *uinfo[16] = {0};
	pgp_keyring_packet *keyring[16] = {0};

	pgp_compresed_packet *compressed = NULL;
	pgp_stream_t *message = NULL;

	uint32_t count = 0;

	pgp_stream_t *stream = NULL;
	pgp_seipd_packet *seipd = NULL;
	pgp_literal_packet *literal = NULL;

	byte_t session_key[64] = {0};
	byte_t session_key_size = 0;

	void *passphrase = NULL;

	if (command.recipients == NULL && command.symmetric == 0)
	{
		printf("No recipient specified\n.");
		exit(1);
	}

	if (command.symmetric)
	{
		if (command.passhprase == NULL)
		{
			passphrase = spgp_prompt_passphrase();

			if (passphrase == NULL)
			{
				printf("No passphrase provided\n.");
				exit(1);
			}
		}
	}

	count = command.recipients->count;

	// Search the keyring to find the keys
	for (uint32_t i = 0; i < count; ++i)
	{
		keyring[i] = spgp_search_keyring(&key[i], &uinfo[i], command.recipients->packets[i], strlen(command.recipients->packets[i]),
										 (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE));

		if (keyring[i] == NULL)
		{
			printf("Unable to find recipient %s\n.", (char *)command.recipients->packets[i]);
			exit(1);
		}

		if (key[i] == NULL)
		{
			printf("No Encryption key for recipient %s\n.", (char *)command.recipients->packets[i]);
			exit(1);
		}
	}

	// Create the encrypted message
	if (command.files == NULL)
	{
		if (command.detach_sign)
		{
			message = spgp_detach_sign_file(key, uinfo, count, NULL);
		}
		if (command.clear_sign)
		{
			message = spgp_clear_sign_file(key, uinfo, count, NULL);
		}
		if (command.sign)
		{
			if (command.mode != SPGP_MODE_RFC2440)
			{
				message = spgp_sign_file(key, uinfo, count, NULL);
			}
			else
			{
				message = spgp_sign_file_legacy(key, uinfo, count, NULL);
			}
		}
	}
	else
	{
		for (uint32_t i = 0; i < count; ++i)
		{
			if (command.detach_sign)
			{
				message = spgp_detach_sign_file(key, uinfo, count, command.files->packets[i]);
			}
			if (command.clear_sign)
			{
				message = spgp_clear_sign_file(key, uinfo, count, command.files->packets[i]);
			}
			if (command.sign)
			{
				if (command.mode != SPGP_MODE_RFC2440)
				{
					message = spgp_sign_file(key, uinfo, count, command.files->packets[i]);
				}
				else
				{
					message = spgp_sign_file_legacy(key, uinfo, count, command.files->packets[i]);
				}
			}
		}
	}

	literal = spgp_literal_read_file(file, PGP_LITERAL_DATA_BINARY);
	lit_buffer = malloc(PGP_PACKET_OCTETS(literal->header));
	pgp_literal_packet_write(literal, lit_buffer, PGP_PACKET_OCTETS(literal->header));

	stream = pgp_stream_new(2);

	if (command->symmetric)
	{
		pgp_skesk_packet *session = NULL;
		pgp_s2k s2k = {.id = PGP_S2K_ITERATED,
					   .iterated = {.hash_id = PGP_SHA1, .count = 200, .salt = {0x06, 0xa1, 0x02, 0x2a, 0x22, 0x51, 0xc1, 0x6a}}};

		if (command->passhprase == NULL)
		{
			printf("Passphrase required.\n");
			exit(1);
		}

		pgp_skesk_packet_new(&session, PGP_SKESK_V4, PGP_AES_128, 0, &s2k);
		pgp_skesk_packet_session_key_encrypt(session, command->passhprase, strlen(command->passhprase), NULL, 0, NULL, 0);

		session_key_size = pgp_s2k_hash(&s2k, command->passhprase, strlen(command->passhprase), session_key, 16);

		pgp_stream_push(stream, session);
	}
	else
	{
		pgp_pkesk_packet *session = NULL;
		pgp_key_packet *key = NULL;

		key = spgp_search_key_from_user(command->user);
		pgp_pkesk_packet_new(&session, PGP_PKESK_V3);

		session_key_size = pgp_rand(session_key, 16);
		pgp_pkesk_packet_session_key_encrypt(session, key, 0, PGP_AES_128, session_key, session_key_size);

		pgp_stream_push(stream, session);
	}

	pgp_seipd_packet_new(&seipd, PGP_SEIPD_V1, PGP_AES_128, 0, 0);
	pgp_seipd_packet_encrypt(seipd, NULL, session_key, session_key_size, NULL);

	pgp_stream_push(stream, seipd);

	spgp_write_pgp_packets(command->output, stream, NULL);

	free(buffer);
	pgp_literal_packet_delete(literal);

	return 0;
}

uint32_t spgp_decrypt(spgp_command *command)
{
	pgp_stream_t *stream = NULL;
	pgp_stream_t *decrypted_stream = NULL;
	pgp_packet_header *header = NULL;

	pgp_seipd_packet *seipd = NULL;
	pgp_literal_packet *literal = NULL;

	byte_t session_key[64] = {0};
	byte_t session_key_size = 64;

	void *file = NULL;
	void *buffer = NULL;
	uint32_t data_size = 0;

	if (command->files != NULL)
	{
		file = command->files->packets[0];
	}

	stream = spgp_read_pgp_packets(file);

	if (stream == NULL)
	{
		printf("Invalid pgp stream.\n");
		exit(1);
	}

	header = stream->packets[0];
	seipd = stream->packets[1];

	if (pgp_packet_get_type(header->tag) == PGP_PKESK)
	{
		pgp_pkesk_packet *session = stream->packets[0];
		pgp_key_packet *key = spgp_search_key_from_user(command->user);

		if (command->passhprase == NULL)
		{
			printf("Passphrase required.\n");
			exit(1);
		}

		pgp_key_packet_decrypt(key, command->passhprase, strlen(command->passhprase));

		pgp_pkesk_packet_session_key_decrypt(session, key, session_key, &session_key_size);
		seipd->symmetric_key_algorithm_id = session->symmetric_key_algorithm_id;
	}

	if (pgp_packet_get_type(header->tag) == PGP_SKESK)
	{
		pgp_skesk_packet *session = stream->packets[0];

		if (command->passhprase == NULL)
		{
			printf("Passphrase required.\n");
			exit(1);
		}

		pgp_skesk_packet_session_key_decrypt(session, command->passhprase, strlen(command->passhprase), session_key, &session_key_size);
		seipd->symmetric_key_algorithm_id = session->symmetric_key_algorithm_id;
	}

	if (session_key_size == 0)
	{
		printf("Invalid encrypted message.\n");
		exit(1);
	}

	data_size = seipd->data_size;
	buffer = malloc(data_size);

	if (buffer == NULL)
	{
		printf("No memory.\n");
		exit(2);
	}

	data_size = pgp_seipd_packet_decrypt(seipd, session_key, session_key_size, &decrypted_stream);

	if (data_size == 0)
	{
		printf("Decryption failure.\n");
		exit(1);
	}

	literal = decrypted_stream->packets[0];
	spgp_literal_write_file(command->output, literal);

	free(buffer);

	return 0;
}
