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
#include <string.h>

uint32_t spgp_import_keys(spgp_command *command)
{
	char buffer[65536] = {0};

	status_t status = 0;
	size_t size = 0;

	file_t file = {0};
	file_t keyring = {0};

	pgp_stream_t *key_stream = NULL;
	pgp_key_packet *key = NULL;
	pgp_user_id_packet *uid = NULL;
	pgp_keyring_packet *keyring_packet = NULL;

	byte_t primary_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};

	if (command->import.file != NULL)
	{
		status = file_open(&file, HANDLE_CWD, command->import.file, strlen(command->import.file), FILE_READ, 65536);

		if (status != OS_STATUS_SUCCESS)
		{
			fprintf(stderr, "File not found: %s\n", command->import.file);
			return 1;
		}

		size = file_read(&file, buffer, 65536);

		file_close(&file);

		key_stream = pgp_stream_read(buffer, size);
	}
	else
	{
		return 2;
	}

	key = key_stream->packets[0];
	uid = key_stream->packets[1];

	pgp_key_fingerprint(key, primary_fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);

	keyring_packet = pgp_keyring_packet_new(key->version, PGP_TRUST_FULL, primary_fingerprint, uid->user_data, uid->header.body_size);

	for (uint16_t i = 2; i < key_stream->count; ++i)
	{
		pgp_packet_header *header = key_stream->packets[i];
		pgp_packet_type type = pgp_packet_get_type(header->tag);

		if (type == PGP_UID)
		{
			pgp_user_id_packet *other_uid = key_stream->packets[i];

			keyring_packet = pgp_keyring_packet_add_uid(keyring_packet, other_uid->user_data, other_uid->header.body_size);
		}

		if (type == PGP_PUBSUBKEY || type == PGP_SECSUBKEY)
		{
			pgp_key_packet *subkey = key_stream->packets[i];
			byte_t subkey_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};

			pgp_key_fingerprint(subkey, subkey_fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);
			keyring_packet = pgp_keyring_packet_add_subkey(keyring_packet, subkey_fingerprint);
		}
	}

	char wb[65536] = {0};

	// Lock the keyring
	
	size_t sz = pgp_keyring_packet_write(keyring_packet, wb, 65536);
	
	file_open(&keyring, command->keyring, NULL, 0, FILE_READ | FILE_WRITE, 65536);
	file_write(&keyring, wb, sz);
	file_close(&keyring);

	// status = os_lock(command->keyring, 0, (size_t)-1, 0, 1);
	//
	// if (status != OS_STATUS_SUCCESS)
	//{
	//	fprintf(stderr, "Unable to lock keyring");
	//	return 1;
	//}
	//
	// os_unlock(command->keyring, 0, (size_t)-1);

	// Assume key stream for now. TODO

	return 0;
}
