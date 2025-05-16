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

static pgp_stream_t *spgp_encrypt_sed(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
									  pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_sed_packet *sed = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = 0;

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	if (recipient_count == 0 && passphrase_count == 1)
	{
		preferred_s2k_algorithm(PGP_KEY_V4, &s2k);
		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, 0, 0, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), NULL, 0, NULL, 0));

		pgp_stream_push(message, skesk);

		PGP_CALL(pgp_s2k_hash(&s2k, passphrases[0], strlen(passphrases[0]), session_key, session_key_size));

		PGP_CALL(pgp_sed_packet_new(&sed));
		PGP_CALL(pgp_sed_packet_encrypt(sed, PGP_AES_256, session_key, session_key_size, stream));

		pgp_stream_push(message, sed);

		return message;
	}

	// Generate the session key
	PGP_CALL(pgp_rand(session_key, session_key_size));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V3));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, PGP_AES_256, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		memset(&s2k, 0, sizeof(pgp_s2k));
		preferred_s2k_algorithm(PGP_KEY_V4, &s2k);

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, PGP_AES_256, 0, &s2k));
		PGP_CALL(
			pgp_skesk_packet_session_key_encrypt(skesk, passphrases[i], strlen(passphrases[i]), NULL, 0, session_key, session_key_size));

		pgp_stream_push(message, skesk);
	}

	PGP_CALL(pgp_sed_packet_new(&sed));
	PGP_CALL(pgp_sed_packet_encrypt(sed, PGP_AES_256, session_key, session_key_size, stream));

	pgp_stream_push(message, sed);

	return message;
}

static pgp_stream_t *spgp_encrypt_mdc(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
									  pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_seipd_packet *seipd = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = 0;

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	if (recipient_count == 0 && passphrase_count == 1)
	{
		preferred_s2k_algorithm(PGP_KEY_V4, &s2k);
		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, 0, 0, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), NULL, 0, NULL, 0));

		pgp_stream_push(message, skesk);

		PGP_CALL(pgp_s2k_hash(&s2k, passphrases[0], strlen(passphrases[0]), session_key, session_key_size));

		PGP_CALL(pgp_seipd_packet_new(&seipd, PGP_SEIPD_V1, PGP_AES_256, 0, 0));
		PGP_CALL(pgp_seipd_packet_encrypt(seipd, NULL, session_key, session_key_size, stream));

		pgp_stream_push(message, seipd);

		return message;
	}

	// Generate the session key
	PGP_CALL(pgp_rand(session_key, session_key_size));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V3));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, PGP_AES_256, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		memset(&s2k, 0, sizeof(pgp_s2k));
		preferred_s2k_algorithm(PGP_KEY_V4, &s2k);

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, PGP_AES_256, 0, &s2k));
		PGP_CALL(
			pgp_skesk_packet_session_key_encrypt(skesk, passphrases[i], strlen(passphrases[i]), NULL, 0, session_key, session_key_size));

		pgp_stream_push(message, skesk);
	}

	PGP_CALL(pgp_seipd_packet_new(&seipd, PGP_SEIPD_V1, PGP_AES_256, 0, 0));
	PGP_CALL(pgp_seipd_packet_encrypt(seipd, NULL, session_key, session_key_size, stream));

	pgp_stream_push(message, seipd);

	return message;
}

static pgp_stream_t *spgp_encrypt_aead(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
									   pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_aead_packet *aead = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = 0;

	byte_t iv[16] = {0};
	byte_t iv_size = pgp_aead_iv_size(PGP_AEAD_OCB);

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	// Generate the session key
	PGP_CALL(pgp_rand(session_key, session_key_size));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V3));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, PGP_AES_256, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		memset(&s2k, 0, sizeof(pgp_s2k));
		preferred_s2k_algorithm(PGP_KEY_V5, &s2k);

		// Generate IV for S2K
		PGP_CALL(pgp_rand(iv, iv_size));

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V5, PGP_AES_128, PGP_AEAD_OCB, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[i], strlen(passphrases[i]), iv, iv_size, session_key,
													  session_key_size));

		pgp_stream_push(message, skesk);
	}

	// Generate IV for encryption
	PGP_CALL(pgp_rand(iv, iv_size));

	PGP_CALL(pgp_aead_packet_new(&aead, PGP_AES_256, PGP_AEAD_OCB, PGP_MAX_CHUNK_SIZE));
	PGP_CALL(pgp_aead_packet_encrypt(aead, iv, iv_size, session_key, session_key_size, stream));

	pgp_stream_push(message, aead);

	return message;
}

static pgp_stream_t *spgp_encrypt_seipd(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
										pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_seipd_packet *seipd = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = 0;

	byte_t iv[16] = {0};
	byte_t iv_size = pgp_aead_iv_size(PGP_AEAD_OCB);

	byte_t salt[32] = {0};
	byte_t salt_size = 32;

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	// Generate the session key
	PGP_CALL(pgp_rand(session_key, session_key_size));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V6));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, PGP_AES_256, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		memset(&s2k, 0, sizeof(pgp_s2k));
		preferred_s2k_algorithm(PGP_KEY_V6, &s2k);

		// Generate IV for S2K
		PGP_CALL(pgp_rand(iv, iv_size));

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V6, PGP_AES_128, PGP_AEAD_OCB, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), iv, iv_size, session_key,
													  session_key_size));

		pgp_stream_push(message, skesk);
	}

	// Generate the salt
	PGP_CALL(pgp_rand(salt, salt_size));

	// Encrypt
	PGP_CALL(pgp_seipd_packet_new(&seipd, PGP_SEIPD_V2, PGP_AES_256, PGP_AEAD_OCB, PGP_MAX_CHUNK_SIZE));
	PGP_CALL(pgp_seipd_packet_encrypt(seipd, salt, session_key, session_key_size, stream));

	pgp_stream_push(message, seipd);

	return message;
}

void spgp_encrypt(void)
{
	pgp_key_packet *key[16] = {0};
	pgp_user_info *uinfo[16] = {0};
	pgp_keyring_packet *keyring[16] = {0};

	pgp_literal_packet *literal = NULL;
	pgp_stream_t *stream = NULL;
	pgp_stream_t *message = NULL;

	uint32_t count = 0;

	armor_options options = {0};
	armor_marker marker = {0};
	armor_options *opts = NULL;

	if (command.encrypt && command.recipients == NULL)
	{
		printf("No recipient specified\n.");
		exit(1);
	}

	if (command.symmetric)
	{
		if (command.passhprases == NULL)
		{
			void *passphrase = spgp_prompt_passphrase();

			if (passphrase == NULL)
			{
				printf("No passphrase provided\n.");
				exit(1);
			}

			STREAM_CALL(command.passhprases = pgp_stream_push(command.passhprases, passphrase));
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

	// Literal or compressed packet
	STREAM_CALL(stream = pgp_stream_new(1));

	// Create the encrypted message
	if (command.files == NULL)
	{
		literal = spgp_literal_read_file(NULL, PGP_LITERAL_DATA_BINARY);
		stream = pgp_stream_push(stream, literal);

		switch (command.mode)
		{
		case SPGP_MODE_RFC2440:
			message = spgp_encrypt_sed(key, count, command.passhprases->packets, command.passhprases->count, stream);
		case SPGP_MODE_RFC4880:
			message = spgp_encrypt_mdc(key, count, command.passhprases->packets, command.passhprases->count, stream);
		case SPGP_MODE_LIBREPGP:
			message = spgp_encrypt_aead(key, count, command.passhprases->packets, command.passhprases->count, stream);
		case SPGP_MODE_OPENPGP:
			message = spgp_encrypt_seipd(key, count, command.passhprases->packets, command.passhprases->count, stream);
		}

		stream = pgp_stream_clear(stream, pgp_packet_delete);
	}
	else
	{
		for (uint32_t i = 0; i < count; ++i)
		{
			literal = spgp_literal_read_file(NULL, PGP_LITERAL_DATA_BINARY);
			stream = pgp_stream_push(stream, literal);

			switch (command.mode)
			{
			case SPGP_MODE_RFC2440:
				message = spgp_encrypt_sed(key, count, command.passhprases->packets, command.passhprases->count, stream);
			case SPGP_MODE_RFC4880:
				message = spgp_encrypt_mdc(key, count, command.passhprases->packets, command.passhprases->count, stream);
			case SPGP_MODE_LIBREPGP:
				message = spgp_encrypt_aead(key, count, command.passhprases->packets, command.passhprases->count, stream);
			case SPGP_MODE_OPENPGP:
				message = spgp_encrypt_seipd(key, count, command.passhprases->packets, command.passhprases->count, stream);
			}

			stream = pgp_stream_clear(stream, pgp_packet_delete);
		}
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

	spgp_write_pgp_packets(command.output, message, opts);
}

static pgp_stream_t *spgp_decrypt_file(void *file)
{
	pgp_error_t status = 0;

	pgp_stream_t *stream = NULL;
	pgp_stream_t *message = NULL;
	pgp_packet_header *header = NULL;

	void *passphrase = NULL;
	byte_t passphrase_size = 0;

	byte_t session_key[32] = {0};
	byte_t session_key_size = 32;
	byte_t session_key_found = 0;

	stream = spgp_read_pgp_packets(file);

	// Search PKESKs first
	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];

		if (pgp_packet_get_type(header->tag) == PGP_PKESK)
		{
			pgp_pkesk_packet *pkesk = stream->packets[i];

			pgp_key_packet *key = NULL;
			pgp_user_info *uinfo = NULL;
			pgp_keyring_packet *keyring = NULL;

			byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
			byte_t fingerprint_size = 0;

			if (pkesk->version == PGP_PKESK_V3)
			{
				fingerprint_size = PGP_KEY_ID_SIZE;
				memcpy(fingerprint, pkesk->key_id, fingerprint_size);
			}
			else
			{
				fingerprint_size = pgp_key_fingerprint_size(pkesk->key_version);
				memcpy(fingerprint, pkesk->key_fingerprint, fingerprint_size);
			}

			keyring =
				spgp_search_keyring(&key, &uinfo, fingerprint, fingerprint_size, (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE));

			if (key != NULL)
			{
				key = spgp_decrypt_key(keyring, key);
				status = pgp_pkesk_packet_session_key_decrypt(pkesk, key, session_key, &session_key_size);

				if (status == PGP_SUCCESS)
				{
					session_key_found = 1;
					goto decrypt;
				}
			}
		}
	}

	// Search SKESKs
	passphrase = spgp_prompt_passphrase();
	passphrase_size = strlen(passphrase);

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];

		if (pgp_packet_get_type(header->tag) == PGP_SKESK)
		{
			pgp_skesk_packet *skesk = stream->packets[i];

			status = pgp_skesk_packet_session_key_decrypt(skesk, passphrase, passphrase_size, session_key, &session_key_size);

			if (status == PGP_SUCCESS)
			{
				session_key_found = 1;
				goto decrypt;
			}
		}
	}

	if (session_key_found == 0)
	{
		printf("Unable to process\n");
		exit(1);
	}

decrypt:
	header = stream->packets[stream->count - 1];

	switch (pgp_packet_get_type(header->tag))
	{
	case PGP_SED:
		PGP_CALL(pgp_sed_packet_decrypt(stream->packets[stream->count - 1], PGP_AES_256, session_key, session_key_size, &message));
	case PGP_SEIPD:
		PGP_CALL(pgp_seipd_packet_decrypt(stream->packets[stream->count - 1], session_key, session_key_size, &message));
	case PGP_AEAD:
		PGP_CALL(pgp_aead_packet_decrypt(stream->packets[stream->count - 1], session_key, session_key_size, &message));
	default:
		printf("Bad PGP Message\n");
		exit(1);
	}

	pgp_stream_delete(stream, pgp_packet_delete);

	return message;
}

void spgp_decrypt(void)
{
	pgp_stream_t *stream = NULL;
	pgp_packet_header *header = NULL;

	if (command.files == NULL)
	{
		stream = spgp_decrypt_file(NULL);
		header = stream->packets[0];

		if (pgp_packet_get_type(header->tag) == PGP_LIT)
		{
			spgp_literal_write_file(command.output, stream->packets[0]);
		}
	}
	else
	{
		for (uint32_t i = 0; i < command.files->count; ++i)
		{
			stream = spgp_decrypt_file(command.files->packets[i]);
			header = stream->packets[0];

			if (pgp_packet_get_type(header->tag) == PGP_LIT)
			{
				spgp_literal_write_file(command.output, stream->packets[0]);
			}
		}
	}
}
