/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <spgp.h>
#include <crypto.h>
#include <packet.h>
#include <key.h>
#include <signature.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

static byte_t hexify(char *buffer, byte_t *fingerprint, byte_t size)
{
	byte_t pos = 0;

	for (uint32_t i = 0; i < size; ++i)
	{
		byte_t a, b;

		a = fingerprint[i] / 16;
		b = fingerprint[i] % 16;

		buffer[pos++] = hex_table[a];
		buffer[pos++] = hex_table[b];
	}

	buffer[pos] = '\0';

	return pos;
}

static byte_t get_key_filename(char *buffer, byte_t *fingerprint, byte_t size)
{
	byte_t pos = 0;

	pos = hexify(buffer, fingerprint, size);

	// Append .key
	buffer[pos++] = '.';
	buffer[pos++] = 'k';
	buffer[pos++] = 'e';
	buffer[pos++] = 'y';
	buffer[pos] = '\0';

	return pos;
}

static byte_t get_cert_filename(char *buffer, byte_t *fingerprint, byte_t size)
{
	byte_t pos = 0;

	pos = hexify(buffer, fingerprint, size);

	// Append .cert
	buffer[pos++] = '.';
	buffer[pos++] = 'c';
	buffer[pos++] = 'e';
	buffer[pos++] = 'r';
	buffer[pos++] = 't';
	buffer[pos] = '\0';

	return pos;
}

static byte_t get_key_passphrase_env(char *buffer, byte_t *fingerprint, byte_t size)
{
	byte_t pos = 0;

	pos = hexify(buffer, fingerprint, size);

	// Append .passphrase
	buffer[pos++] = '.';
	buffer[pos++] = 'p';
	buffer[pos++] = 'a';
	buffer[pos++] = 's';
	buffer[pos++] = 's';
	buffer[pos++] = 'p';
	buffer[pos++] = 'h';
	buffer[pos++] = 'r';
	buffer[pos++] = 'a';
	buffer[pos++] = 's';
	buffer[pos++] = 'e';
	buffer[pos] = '\0';

	return pos;
}

pgp_stream_t *spgp_read_certificate(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t fingerprint_size)
{
	handle_t handle = 0;
	size_t result = 0;

	pgp_stream_t *stream = NULL;

	char buffer[16384] = {0};
	char filename[256] = {0};
	uint32_t length = 0;

	length = get_cert_filename(filename, fingerprint, fingerprint_size);

	OS_CALL(os_open(&handle, command.certs, filename, length, FILE_ACCESS_READ, 0, 0),
			printf("Unable to open certificate file %s", filename));
	OS_CALL(os_read(handle, buffer, 16384, &result), printf("Unable to read certificate file %s", filename));

	PGP_CALL(pgp_packet_stream_read(&stream, buffer, result));

	OS_CALL(os_close(handle), printf("Unable to close handle %u", (uint32_t)(uintptr_t)handle));

	return stream;
}

void spgp_write_certificate(pgp_stream_t *stream)
{
	handle_t handle = 0;
	size_t result = 0;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	char filename[256] = {0};
	uint32_t length = 0;

	void *buffer = NULL;
	size_t size = 0;

	PGP_CALL(pgp_key_fingerprint(stream->packets[0], fingerprint, &fingerprint_size));
	length = get_cert_filename(filename, fingerprint, fingerprint_size);

	PGP_CALL(pgp_packet_stream_write(stream, &buffer, &size));

	OS_CALL(os_open(&handle, command.certs, filename, length, FILE_ACCESS_WRITE, FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE, 0700),
			printf("Unable to open certificate file %s", filename));
	OS_CALL(os_write(handle, buffer, size, &result), printf("Unable to write certificate file %s", filename));
	OS_CALL(os_close(handle), printf("Unable to close handle %u", (uint32_t)(uintptr_t)handle));

	free(buffer);
}

pgp_key_packet *spgp_read_key(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t fingerprint_size)
{
	handle_t handle = 0;
	size_t result = 0;

	pgp_key_packet *key = NULL;

	char buffer[16384] = {0};
	char filename[256] = {0};
	uint32_t length = 0;

	length = get_key_filename(filename, fingerprint, fingerprint_size);

	OS_CALL(os_open(&handle, command.keys, filename, length, FILE_ACCESS_READ, 0, 0), printf("Unable to open key file %s", filename));
	OS_CALL(os_read(handle, buffer, 16384, &result), printf("Unable to read key file %s", filename));

	PGP_CALL(pgp_key_packet_read(&key, buffer, result));

	OS_CALL(os_close(handle), printf("Unable to close handle %u", (uint32_t)(uintptr_t)handle));

	return key;
}

void spgp_write_key(pgp_key_packet *key)
{
	handle_t handle = 0;
	size_t result = 0;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	char buffer[16384] = {0};
	char filename[256] = {0};
	uint32_t length = 0;

	PGP_CALL(pgp_key_fingerprint(key, fingerprint, &fingerprint_size));
	length = get_key_filename(filename, fingerprint, fingerprint_size);

	pgp_key_packet_write(key, buffer, 16384);

	OS_CALL(os_open(&handle, command.keys, filename, length, FILE_ACCESS_WRITE, FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE, 0700),
			printf("Unable to open key file %s", filename));
	OS_CALL(os_write(handle, buffer, PGP_PACKET_OCTETS(key->header), &result), printf("Unable to write key file %s", filename));
	OS_CALL(os_close(handle), printf("Unable to close handle %u", (uint32_t)(uintptr_t)handle));
}

static void spgp_import_certificates(pgp_stream_t *stream)
{
	pgp_packet_header *header = NULL;
	pgp_packet_type type = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_KEYDEF)
		{
			if (i == 0)
			{
				PGP_CALL(pgp_key_packet_transform(stream->packets[i], PGP_PUBKEY));
			}
			else
			{
				PGP_CALL(pgp_key_packet_transform(stream->packets[i], PGP_PUBSUBKEY));
			}
		}
	}

	spgp_write_certificate(stream);
}

pgp_stream_t *spgp_read_keyring()
{
	// Read the entire keyring only once
	if (command.keyring_stream == NULL)
	{
		command.keyring_stream = spgp_read_pgp_packets_from_handle(command.keyring);

		// Make sure the keyring is mutable
		if (command.keyring_stream == &command.empty_stream)
		{
			STREAM_CALL(command.keyring_stream = pgp_stream_new(4));
		}
	}

	return command.keyring_stream;
}

pgp_keyring_packet *spgp_search_keyring(pgp_key_packet **key, pgp_user_info **user, void *input, uint32_t size, byte_t capabilities)
{
	pgp_stream_t *stream = spgp_read_keyring();
	pgp_keyring_packet *keyring = NULL;
	pgp_user_info *uinfo = NULL;

	if (stream == NULL)
	{
		return NULL;
	}

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		uinfo = pgp_keyring_packet_search(stream->packets[i], input, size);

		if (uinfo != NULL)
		{
			keyring = stream->packets[i];
			break;
		}
	}

	if (keyring == NULL)
	{
		return NULL;
	}

	// Find a key with necessary capabilities
	if (key != NULL)
	{
		*key = spgp_read_key(uinfo->fingerprint, uinfo->fingerprint_size);

		if (((*key)->capabilities & capabilities) == 0)
		{
			pgp_key_packet_delete(*key);
			*key = NULL;

			// Check if the fingerprint given was the primary key's one.
			if (memcmp(keyring->primary_fingerprint, uinfo->fingerprint, uinfo->fingerprint_size) == 0)
			{
				// Search the subkeys for a suitable key
				for (byte_t i = 0; i < keyring->subkey_count; ++i)
				{
					*key =
						spgp_read_key(PTR_OFFSET(keyring->subkey_fingerprints, i * keyring->fingerprint_size), keyring->fingerprint_size);

					if (((*key)->capabilities & capabilities) == capabilities)
					{
						break;
					}

					// Free memory for unusable keys
					pgp_key_packet_delete(*key);
					*key = NULL;
				}
			}
		}
	}

	if (user != NULL)
	{
		*user = uinfo;
	}

	return keyring;
}

uint32_t spgp_update_keyring(pgp_keyring_packet *keyring, uint32_t options)
{
	pgp_stream_t *stream = NULL;
	pgp_keyring_packet *packet = NULL;
	byte_t matching_keyring_found = 0;
	uint16_t keyring_index = 0;

	stream = spgp_read_keyring();

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		packet = stream->packets[i];

		if (packet->key_version == keyring->key_version &&
			memcmp(packet->primary_fingerprint, keyring->primary_fingerprint, keyring->fingerprint_size) == 0)
		{
			matching_keyring_found = 1;
			keyring_index = i;

			break;
		}
	}

	if (matching_keyring_found)
	{
		if (options & SPGP_KEYRING_REPLACE)
		{
			// Update the keyring
			pgp_keyring_packet_delete(stream->packets[keyring_index]);
			stream->packets[keyring_index] = keyring;
		}
		else
		{
			return 1;
		}
	}
	else
	{
		STREAM_CALL(stream = pgp_stream_push(stream, keyring));
	}

	OS_CALL(os_seek(command.keyring, 0, SEEK_SET), printf("Unable to seek keyring"));
	OS_CALL(os_truncate(command.keyring, NULL, 0, 0), printf("Unable to trucate keyring"));

	spgp_write_pgp_packets_handle(command.keyring, stream, NULL);

	return 0;
}

static uint32_t spgp_process_transferable_key(pgp_stream_t *stream, uint32_t offset)
{
	pgp_error_t status = 0;
	uint32_t end = 0;
	uint32_t pos = 0;

	pgp_packet_header *header = NULL;
	pgp_packet_type type = 0;

	pgp_key_packet *primary_key = NULL;
	pgp_key_packet *subkey = NULL;
	pgp_key_packet *other_key = NULL;
	pgp_key_type key_type = 0;

	pgp_user_id_packet *uid = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_keyring_packet *keyring_packet = NULL;
	pgp_user_info *uinfo = NULL;

	pgp_stream_t certificate = {0};

	byte_t primary_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t primary_fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	byte_t subkey_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t subkey_fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	byte_t signature_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t signature_fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	byte_t signature_by_primary_key = 0;
	byte_t certificate_version = 0;

	// The first packet must be public key or secret key packet
	header = stream->packets[offset + pos];
	type = pgp_packet_type_from_tag(header->tag);

	if (type != PGP_PUBKEY && type != PGP_SECKEY)
	{
		printf("Bad PGP Key certificate.\n");
		exit(1);
	}

	primary_key = stream->packets[offset + pos];
	key_type = (type == PGP_PUBKEY) ? PGP_KEY_TYPE_PUBLIC : PGP_KEY_TYPE_SECRET;
	certificate_version = primary_key->version;
	pos += 1;

	if (pgp_signature_algorithm_validate(primary_key->public_key_algorithm_id) == 0)
	{
		printf("Invalid top level key algorithm.\n");
		exit(1);
	}

	for (uint32_t i = offset + 1; i < stream->count; ++i)
	{
		header = stream->packets[i];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_PUBKEY || type == PGP_SECKEY)
		{
			end = i;
			break;
		}

		if (key_type == PGP_KEY_TYPE_PUBLIC)
		{
			if (type == PGP_SECSUBKEY)
			{
				printf("Bad PGP Key certificate.\n");
				exit(1);
			}
		}
		else
		{
			if (type == PGP_PUBSUBKEY)
			{
				printf("Bad PGP Key certificate.\n");
				exit(1);
			}
		}
	}

	if (end == 0)
	{
		end = stream->count;
	}

	// Calculate the primary key fingerprint
	PGP_CALL(pgp_key_fingerprint(primary_key, primary_fingerprint, &primary_fingerprint_size));

	// Initialize the keyring packet
	PGP_CALL(pgp_keyring_packet_new(&keyring_packet, primary_key->version, primary_fingerprint, NULL));

	// Next should be direct key signatures
	while ((offset + pos) < end)
	{
		header = stream->packets[offset + pos];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_UID || type == PGP_UAT)
		{
			break;
		}

		if (type == PGP_SIG)
		{
			signature_by_primary_key = 0;
			sign = stream->packets[offset + pos];
			signature_fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

			if (certificate_version != sign->version)
			{
				printf("Version of primary key and signature packet should be the same.\n");
				exit(1);
			}

			PGP_CALL(pgp_signature_get_key_fingerprint(sign, signature_fingerprint, &signature_fingerprint_size));

			// Only allowed signature types
			if (sign->type != PGP_DIRECT_KEY_SIGNATURE && sign->type != PGP_KEY_REVOCATION_SIGNATURE)
			{
				printf("Invalid signature type on keys.\n");
				exit(1);
			}

			if (pgp_key_compare(primary_key, signature_fingerprint, signature_fingerprint_size) == 0)
			{
				signature_by_primary_key = 1;
			}

			if (sign->type == PGP_DIRECT_KEY_SIGNATURE)
			{
				if (signature_by_primary_key == 0)
				{
					printf("Direct key signatures should be issued by primary keys.\n");
					exit(1);
				}
			}

			PGP_CALL(pgp_key_packet_make_definition(primary_key, sign));

			// Check the signature
			if (signature_by_primary_key)
			{
				status = spgp_verify_signature(sign, primary_key, NULL, primary_key, 0);

				if (status != PGP_SUCCESS)
				{
					exit(1);
				}
			}
			else
			{
				// Search for the key
				other_key = NULL;

				spgp_search_keyring(&other_key, NULL, signature_fingerprint, signature_fingerprint_size,
									PGP_KEY_FLAG_CERTIFY | PGP_KEY_FLAG_SIGN);

				if (other_key != NULL)
				{
					status = spgp_verify_signature(sign, other_key, NULL, primary_key, 0);

					if (status != PGP_SUCCESS)
					{
						// Don't exit in this case
						printf("Bad signature.\n");
					}
				}
			}
		}

		pos += 1;
	}

	// User packets and signatures
	while ((offset + pos) < end)
	{
		header = stream->packets[offset + pos];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_PUBSUBKEY || type == PGP_SECSUBKEY)
		{
			if (uinfo != NULL)
			{
				PGP_CALL(pgp_keyring_packet_add_user(keyring_packet, uinfo));
				uinfo = NULL;
			}

			break;
		}

		if (type == PGP_UID || type == PGP_UAT)
		{
			uid = stream->packets[offset + pos];

			if (uinfo != NULL)
			{
				PGP_CALL(pgp_keyring_packet_add_user(keyring_packet, uinfo));
				uinfo = NULL;
			}
		}

		if (type == PGP_SIG)
		{
			signature_by_primary_key = 0;
			sign = stream->packets[offset + pos];
			signature_fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

			if (certificate_version != sign->version)
			{
				printf("Version of primary key and signature packet should be the same.\n");
				exit(1);
			}

			PGP_CALL(pgp_signature_get_key_fingerprint(sign, signature_fingerprint, &signature_fingerprint_size));

			// Only use User ID packets for information
			if (pgp_packet_type_from_tag(uid->header.tag) == PGP_UID)
			{
				if (pgp_key_compare(primary_key, signature_fingerprint, signature_fingerprint_size) == 0)
				{
					signature_by_primary_key = 1;

					if (sign->type == PGP_GENERIC_CERTIFICATION_SIGNATURE || sign->type == PGP_PERSONA_CERTIFICATION_SIGNATURE ||
						sign->type == PGP_CASUAL_CERTIFICATION_SIGNATURE || sign->type == PGP_POSITIVE_CERTIFICATION_SIGNATURE)
					{
						PGP_CALL(pgp_key_packet_make_definition(primary_key, sign));
					}

					PGP_CALL(pgp_user_info_from_certificate(&uinfo, uid, sign));
				}
			}

			// Check the signature
			if (signature_by_primary_key)
			{
				status = spgp_verify_signature(sign, primary_key, NULL, uid, 0);

				if (status != PGP_SUCCESS)
				{
					printf("Bad signature.\n");
					exit(1);
				}
			}
			else
			{
				// Search for the key
				other_key = NULL;

				spgp_search_keyring(&other_key, NULL, signature_fingerprint, signature_fingerprint_size,
									PGP_KEY_FLAG_CERTIFY | PGP_KEY_FLAG_SIGN);

				if (other_key != NULL)
				{
					status = spgp_verify_signature(sign, other_key, NULL, uid, 0);

					if (status != PGP_SUCCESS)
					{
						// Don't exit in this case
						printf("Bad signature.\n");
					}
				}
			}
		}

		pos += 1;
	}

	// Check whether the primary key has certification capability
	if ((primary_key->capabilities & PGP_KEY_FLAG_CERTIFY) == 0)
	{
		printf("Primary key cannot certify.\n");
		exit(1);
	}

	// Subkeys and signatures
	while ((offset + pos) < end)
	{
		header = stream->packets[offset + pos];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_PUBSUBKEY || type == PGP_SECSUBKEY)
		{
			subkey = stream->packets[offset + pos];

			if (certificate_version != subkey->version)
			{
				printf("Version of primary key and subkeys should be the same.\n");
				exit(1);
			}

			PGP_CALL(pgp_key_fingerprint(subkey, subkey_fingerprint, &subkey_fingerprint_size));
			PGP_CALL(pgp_keyring_packet_add_subkey(keyring_packet, subkey_fingerprint));
		}

		if (type == PGP_SIG)
		{
			signature_by_primary_key = 0;
			sign = stream->packets[offset + pos];
			signature_fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

			if (certificate_version != sign->version)
			{
				printf("Version of primary key and signature packet should be the same.\n");
				exit(1);
			}

			PGP_CALL(pgp_signature_get_key_fingerprint(sign, signature_fingerprint, &signature_fingerprint_size));

			if (pgp_key_compare(primary_key, signature_fingerprint, signature_fingerprint_size) == 0)
			{
				signature_by_primary_key = 1;
			}

			if (sign->type == PGP_SUBKEY_BINDING_SIGNATURE)
			{
				if (signature_by_primary_key == 0)
				{
					printf("Subkey binding signatures should be issued by primary keys.\n");
					exit(1);
				}
			}

			PGP_CALL(pgp_key_packet_make_definition(subkey, sign));

			// Check the signature
			if (signature_by_primary_key)
			{
				status = spgp_verify_signature(sign, primary_key, NULL, subkey, 0);

				if (status != PGP_SUCCESS)
				{
					printf("Bad signature.\n");
					exit(1);
				}
			}
			else
			{
				// Search for the key
				other_key = NULL;

				spgp_search_keyring(&other_key, NULL, signature_fingerprint, signature_fingerprint_size,
									PGP_KEY_FLAG_CERTIFY | PGP_KEY_FLAG_SIGN);

				if (other_key != NULL)
				{
					status = spgp_verify_signature(sign, other_key, NULL, subkey, 0);

					if (status != PGP_SUCCESS)
					{
						// Don't exit in this case
						printf("Bad signature.\n");
					}
				}
			}
		}

		pos += 1;
	}

	// Write the keys
	spgp_write_key(primary_key);

	for (uint32_t i = offset + 1; i < end; ++i)
	{
		header = stream->packets[i];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_KEYDEF)
		{
			subkey = stream->packets[i];
			spgp_write_key(subkey);
		}
	}

	// Write the certificate
	certificate.packets = &stream->packets[offset];
	certificate.count = end - offset;

	spgp_import_certificates(&certificate);

	// Update the keyring
	spgp_update_keyring(keyring_packet, SPGP_KEYRING_REPLACE);

	return end;
}

static uint32_t spgp_import_key_file(void *file)
{
	pgp_stream_t *stream = NULL;
	uint32_t offset = 0;
	uint32_t count = 0;

	stream = spgp_read_pgp_packets(file);
	stream = pgp_packet_stream_filter_padding_packets(stream);

	while (offset < stream->count)
	{
		offset = spgp_process_transferable_key(stream, offset);
		count += 1;
	}

	return count;
}

void spgp_import_keys(void)
{
	uint32_t count = 0;

	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		count += spgp_import_key_file(command.args->packets[i]);
	}

	printf("Processed %u keys.\n", count);
}

static pgp_stream_t *spgp_export_keyring(void *input, byte_t secret)
{
	pgp_keyring_packet *keyring = NULL;
	pgp_key_packet *key = NULL;
	pgp_stream_t *certificate = NULL;

	uint16_t subkey_index = 0;

	if (input == NULL)
	{
		return NULL;
	}

	keyring = spgp_search_keyring(NULL, NULL, input, strlen(input), 0);

	if (keyring == NULL)
	{
		printf("User not found.\n");
		exit(1);
	}

	// Export the certificate
	certificate = spgp_read_certificate(keyring->primary_fingerprint, keyring->fingerprint_size);
	certificate = pgp_packet_stream_filter_non_exportable_signatures(certificate);

	// Replace the public keys with secret keys
	if (secret)
	{
		// First key packet is the primary key
		key = spgp_read_key(keyring->primary_fingerprint, keyring->fingerprint_size);

		if (key->type != PGP_KEY_TYPE_SECRET)
		{
			printf("Key is a public key.\n");
			exit(1);
		}

		pgp_packet_delete(certificate->packets[0]);

		pgp_key_packet_transform(key, PGP_SECKEY);
		certificate->packets[0] = key;

		for (uint32_t i = 1; i < certificate->count; ++i)
		{
			pgp_packet_header *header = certificate->packets[i];
			pgp_packet_type type = pgp_packet_type_from_tag(header->tag);

			// The order of subkeys in the keyring and in the certificate will be the same.
			if (type == PGP_PUBSUBKEY)
			{
				key = spgp_read_key(PTR_OFFSET(keyring->subkey_fingerprints, subkey_index * keyring->fingerprint_size),
									keyring->fingerprint_size);

				if (key->type != PGP_KEY_TYPE_SECRET)
				{
					printf("Key is a public key.\n");
					exit(1);
				}

				pgp_packet_delete(certificate->packets[i]);

				pgp_key_packet_transform(key, PGP_SECSUBKEY);
				certificate->packets[i] = key;

				subkey_index += 1;
			}
		}
	}

	return certificate;
}

void spgp_export_keys(void)
{
	handle_t handle = 0;

	pgp_stream_t *certificate = NULL;
	pgp_key_packet *key = NULL;

	armor_options options = {0};
	armor_marker marker = {0};
	armor_options *opts = NULL;

	if (command.armor)
	{
		if (command.export_secret_keys)
		{
			marker = (armor_marker){.header_line = PGP_ARMOR_BEGIN_PRIVATE_KEY,
									.header_line_size = strlen(PGP_ARMOR_BEGIN_PRIVATE_KEY),
									.trailer_line = PGP_ARMOR_END_PRIVATE_KEY,
									.trailer_line_size = strlen(PGP_ARMOR_END_PRIVATE_KEY)};
		}
		else
		{
			marker = (armor_marker){.header_line = PGP_ARMOR_BEGIN_PUBLIC_KEY,
									.header_line_size = strlen(PGP_ARMOR_BEGIN_PUBLIC_KEY),
									.trailer_line = PGP_ARMOR_END_PUBLIC_KEY,
									.trailer_line_size = strlen(PGP_ARMOR_END_PUBLIC_KEY)};
		}

		options.marker = &marker;
		options.flags = ARMOR_EMPTY_LINE | ARMOR_CRLF_ENDING; // | ((keyring->key_version == PGP_KEY_V6) ? 0 : ARMOR_CHECKSUM_CRC24);

		opts = &options;
	}

	if (command.output != NULL)
	{
		OS_CALL(os_open(&handle, HANDLE_CWD, command.output, strlen(command.output), FILE_ACCESS_WRITE,
						FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE, 0700),
				printf("Unable to open file %s", (char *)command.output));
	}
	else
	{
		handle = STDOUT_HANDLE;
	}

	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		certificate = spgp_export_keyring(command.args->data[i], command.export_secret_keys);

		if (certificate == NULL)
		{
			continue;
		}

		if (command.armor)
		{
			key = certificate->packets[0];

			// Add crc24 checksum to armor
			if (key->version != PGP_KEY_V6)
			{
				options.flags |= ARMOR_CHECKSUM_CRC24;
			}
		}

		spgp_write_pgp_packets_handle(handle, certificate, opts);
		pgp_stream_delete(certificate, pgp_packet_delete);
	}

	if (command.output != NULL)
	{
		OS_CALL(os_close(handle), printf("Unable to close handle %u", OS_HANDLE_AS_UINT(handle)));
	}
}

static size_t print_prefix(byte_t primary, byte_t secret, void *str, size_t size)
{
	if (primary && secret)
	{
		return snprintf(str, size, "sec");
	}
	else if (primary && !secret)
	{
		return snprintf(str, size, "pub");
	}
	else if (!primary && secret)
	{
		return snprintf(str, size, "ssb");
	}
	else // if (!primary && !secret)
	{
		return snprintf(str, size, "sub");
	}
}

static size_t print_algorithm(pgp_key_packet *key, void *str, size_t size)
{
	switch (key->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *rsa_key = key->key;
		return snprintf(str, size, "rsa%u", ROUND_UP(rsa_key->n->bits, 1024));
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *elgmal_key = key->key;
		return snprintf(str, size, "elg%u", ROUND_UP(elgmal_key->p->bits, 1024));
	}
	case PGP_DSA:
	{
		pgp_dsa_key *dsa_key = key->key;
		return snprintf(str, size, "dsa%u", ROUND_UP(dsa_key->p->bits, 1024));
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
		case PGP_EC_CURVE25519:
			curve = "cv25519";
			break;
		case PGP_EC_CURVE448:
			curve = "cv448";
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

		return snprintf(str, size, "%s", curve);
	}
	case PGP_X25519:
		return snprintf(str, size, "x25519");
	case PGP_X448:
		return snprintf(str, size, "x448");
	case PGP_ED25519:
		return snprintf(str, size, "ed25519");
	case PGP_ED448:
		return snprintf(str, size, "ed448");
	default:
		return snprintf(str, size, "unknown");
	}
}

static size_t print_capabilities(pgp_key_packet *key, void *str, size_t size)
{
	size_t pos = 0;

	if (key->capabilities == 0)
	{
		return 0;
	}

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "[");

	if (key->capabilities & PGP_KEY_FLAG_CERTIFY)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "C");
	}

	if (key->capabilities & PGP_KEY_FLAG_SIGN)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "S");
	}

	if (key->capabilities & (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE))
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "E");
	}

	if (key->capabilities & PGP_KEY_FLAG_AUTHENTICATION)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "A");
	}

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "]");

	return pos;
}

static size_t print_times(pgp_key_packet *key, void *str, size_t size)
{
	time_t timestamp = 0;
	char date_buffer[64] = {0};
	size_t pos = 0;

	// Creation time
	timestamp = key->key_creation_time;
	strftime(date_buffer, 64, "%Y-%m-%d %H:%M:%S", gmtime(&timestamp));
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "[created: %s]", date_buffer);

	// Expiry time
	if (key->key_expiry_seconds != 0)
	{
		time_t current_time = time(NULL);

		memset(date_buffer, 0, 64);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, " ");

		if (key->version > PGP_KEY_V3)
		{
			timestamp = key->key_creation_time + key->key_expiry_seconds;
		}
		else
		{
			timestamp = key->key_creation_time + (key->key_expiry_days * 86400);
		}

		strftime(date_buffer, 64, "%Y-%m-%d %H:%M:%S", gmtime(&timestamp));

		if (current_time > timestamp)
		{
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "[expired: %s]", date_buffer);
		}
		else
		{
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "[expires: %s]", date_buffer);
		}
	}

	return pos;
}

static size_t print_fingerprint(byte_t *fingerprint, byte_t size, byte_t *out)
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

static size_t print_key(pgp_key_packet *key, byte_t primary, byte_t secret, byte_t *fingerprint, byte_t fingerprint_size, void *str,
						size_t str_size)
{
	size_t pos = 0;

	pos += print_prefix(primary, secret, PTR_OFFSET(str, pos), str_size - pos);
	pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "   "); // 3 spaces

	pos += print_algorithm(key, PTR_OFFSET(str, pos), str_size - pos);
	pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, " ");

	pos += print_capabilities(key, PTR_OFFSET(str, pos), str_size - pos);
	pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, " ");

	pos += print_times(key, PTR_OFFSET(str, pos), str_size - pos);
	pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "\n");

	pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "         "); // 9 spaces
	pos += print_fingerprint(fingerprint, fingerprint_size, PTR_OFFSET(str, pos));
	pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "\n");

	return pos;
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

static size_t print_uid(byte_t *uid, uint32_t uid_size, byte_t trust, void *str, size_t size)
{
	return snprintf(str, size, "uid         [%s] %.*s\n", get_trust_value(trust), uid_size, uid); // 9 spaces
}

void spgp_list_keys(void)
{
	pgp_stream_t *stream = NULL;
	pgp_keyring_packet *keyring = NULL;
	pgp_key_packet *key = NULL;
	pgp_user_info *uinfo = NULL;

	char buffer[65536] = {0};
	size_t size = 65536;
	size_t pos = 0;

	stream = spgp_read_keyring();

	if (stream == NULL)
	{
		return;
	}

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		keyring = stream->packets[i];

		key = spgp_read_key(keyring->primary_fingerprint, keyring->fingerprint_size);

		if (command.list_secret_keys)
		{
			// Skip non secret keys
			if (key->type == PGP_KEY_TYPE_PUBLIC)
			{
				continue;
			}
		}

		// Primary key
		pos += print_key(key, 1, command.list_secret_keys, keyring->primary_fingerprint, keyring->fingerprint_size, PTR_OFFSET(buffer, pos),
						 size - pos);

		// Add uids
		for (byte_t j = 0; j < keyring->users->count; ++j)
		{
			uinfo = keyring->users->packets[j];
			pos += print_uid(uinfo->uid, uinfo->uid_octets, uinfo->trust, PTR_OFFSET(buffer, pos), size - pos);
		}

		// Add subkeys
		for (uint16_t j = 0; j < keyring->subkey_count; ++j)
		{
			key = spgp_read_key(PTR_OFFSET(keyring->subkey_fingerprints, keyring->fingerprint_size * j), keyring->fingerprint_size);
			pos += print_key(key, 0, command.list_secret_keys, PTR_OFFSET(keyring->subkey_fingerprints, keyring->fingerprint_size * j),
							 keyring->fingerprint_size, PTR_OFFSET(buffer, pos), size - pos);
		}

		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "\n");
	}

	printf("%s", buffer);
}

pgp_key_packet *spgp_decrypt_key(pgp_keyring_packet *keyring, pgp_key_packet *key)
{
	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	char passphrase_env[128] = {0};
	void *passphrase = NULL;

	byte_t passphrase_buffer[128] = {0};
	uint32_t passphrase_size = 0;

	char message_buffer[256] = {0};

	// Check if key needs decryption
	if (key->encrypted == NULL && key->encrypted_octets == 0)
	{
		return key;
	}

	PGP_CALL(pgp_key_fingerprint(key, fingerprint, &fingerprint_size));
	get_key_passphrase_env(passphrase_env, fingerprint, fingerprint_size);

	passphrase = getenv(passphrase_env);

	if (passphrase != NULL)
	{
		passphrase_size = strlen(passphrase);
	}

	if (passphrase == NULL)
	{
		// Try the primary key fingerprint
		if (memcmp(fingerprint, keyring->primary_fingerprint, fingerprint_size) != 0)
		{
			get_key_passphrase_env(passphrase_env, keyring->primary_fingerprint, fingerprint_size);
			passphrase = getenv(passphrase_env);

			if (passphrase != NULL)
			{
				passphrase_size = strlen(passphrase);
			}
		}
	}

	// Prompt the user for password
	if (passphrase == NULL)
	{
		// Allow upto 3 retries
		pgp_error_t status = 0;

		byte_t max_retries = 3;
		byte_t retry_count = 0;

		while (retry_count < max_retries)
		{
			if (retry_count == 0)
			{
				snprintf(message_buffer, 256, "Enter passhrase for decrypting key %.*s.", fingerprint_size * 2, passphrase_env);
				passphrase_size = spgp_prompt_passphrase(passphrase_buffer, message_buffer);
			}
			else
			{
				snprintf(message_buffer, 256, "Enter passhrase for decrypting key %.*s (Retries %hhu of %hhu).", fingerprint_size * 2,
						 passphrase_env, retry_count + 1, max_retries);
				passphrase_size = spgp_prompt_passphrase(passphrase_buffer, message_buffer);
			}

			status = pgp_key_packet_decrypt(key, passphrase_buffer, passphrase_size);

			if (status == PGP_SUCCESS)
			{
				return key;
			}

			if (status != PGP_KEY_CHECKSUM_MISMATCH && status != PGP_MDC_TAG_MISMATCH && status != PGP_AEAD_TAG_MISMATCH)
			{
				printf("%s\n", pgp_error(status));
				exit(1);
			}

			retry_count += 1;
		}
	}

	if (passphrase_size == 0)
	{
		printf("Key passphrase not provided.\n");
		exit(1);
	}

	PGP_CALL(pgp_key_packet_decrypt(key, passphrase, strlen(passphrase)));

	return key;
}

uint32_t spgp_prompt_passphrase(byte_t passphrase[SPGP_MAX_PASSPHRASE_SIZE], char *message)
{
	uint32_t is_input_tty = 0;
	uint32_t is_output_tty = 0;

	char buffer[256] = {0};
	size_t result = 0;

	// TODO: Change terminal settings
	OS_CALL(os_isatty(STDIN_HANDLE, &is_input_tty), printf("Unable to check terminal"));
	OS_CALL(os_isatty(STDOUT_HANDLE, &is_output_tty), printf("Unable to check terminal"));

	if (is_input_tty == 0 || is_output_tty == 0)
	{
		return 0;
	}

	result = snprintf(buffer, 256, "%s\r\nPassword: ", message);

	// Write the message
	OS_CALL(os_write(STDOUT_HANDLE, buffer, result, &result), NULL);

	// Read the input
	result = 0;

	OS_CALL(os_read(STDIN_HANDLE, passphrase, SPGP_MAX_PASSPHRASE_SIZE, &result), NULL);

	if (result == 0)
	{
		return 0;
	}

	return (uint32_t)result;
}
