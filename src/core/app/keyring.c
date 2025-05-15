/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <spgp.h>
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
	char filename[256] = {0};

	get_cert_filename(filename, fingerprint, fingerprint_size);

	return spgp_read_pgp_packets(filename);
}

void spgp_write_certificate(pgp_stream_t *stream)
{
	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	char filename[256] = {0};

	PGP_CALL(pgp_key_fingerprint(stream->packets[0], fingerprint, &fingerprint_size));
	get_cert_filename(filename, fingerprint, fingerprint_size);

	spgp_write_pgp_packets(filename, stream, NULL);
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
		type = pgp_packet_get_type(header->tag);

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

		if (type == PGP_SECKEY)
		{
			PGP_CALL(pgp_key_packet_transform(stream->packets[i], PGP_PUBKEY));
		}

		if (type == PGP_SECSUBKEY)
		{
			PGP_CALL(pgp_key_packet_transform(stream->packets[i], PGP_PUBSUBKEY));
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
	}

	return command.keyring_stream;
}

pgp_keyring_packet *spgp_search_keyring(pgp_key_packet **key, pgp_user_info **user, void *input, uint32_t size, byte_t capabilities)
{
	pgp_stream_t *stream = spgp_read_keyring();
	pgp_keyring_packet *keyring = NULL;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		*user = pgp_keyring_packet_search(stream->packets[i], input, size);

		if (*user != NULL)
		{
			// Prevent the packet from being free'd.
			keyring = stream->packets[i];
			stream->packets[i] = NULL;

			break;
		}
	}

	pgp_stream_delete(stream, pgp_packet_delete);

	if (keyring != NULL)
	{
		// Find a key with necessary capabilities
		if ((*user)->fingerprint_size != 0)
		{
			*key = spgp_read_key((*user)->fingerprint, (*user)->fingerprint_size);

			if ((*key)->capabilities & capabilities)
			{

				// Check if the fingerprint given was the primary key's one.
				if (memcmp(keyring->primary_fingerprint, (*user)->fingerprint, (*user)->fingerprint_size) != 0)
				{
					// Search the subkeys for a suitable key
					for (byte_t i = 0; i < keyring->subkey_count; ++i)
					{
						pgp_key_packet_delete(*key);
						*key = spgp_read_key(PTR_OFFSET(keyring->subkey_fingerprints, i * keyring->fingerprint_size),
											 keyring->fingerprint_size);

						if (((*key)->capabilities & capabilities) == capabilities)
						{
							break;
						}
					}
				}
				else
				{
					printf("Unusable key\n");
					exit(1);
				}
			}
		}
	}

	return keyring;
}

uint32_t spgp_update_keyring(pgp_keyring_packet *key, uint32_t options)
{
	pgp_stream_t *stream = NULL;
	pgp_keyring_packet *packet = NULL;
	byte_t matching_keyring_found = 0;
	uint16_t keyring_index = 0;

	stream = spgp_read_keyring();

	if (stream != NULL)
	{
		for (uint32_t i = 0; i < stream->count; ++i)
		{
			packet = stream->packets[i];

			if (packet->key_version == key->key_version &&
				memcmp(packet->primary_fingerprint, key->primary_fingerprint, key->fingerprint_size) == 0)
			{
				matching_keyring_found = 1;
				keyring_index = i;
			}
		}
	}

	if (matching_keyring_found)
	{
		if (options & SPGP_KEYRING_REPLACE)
		{
			// Update the keyring
			pgp_keyring_packet_delete(stream->packets[keyring_index]);
			stream->packets[keyring_index] = key;
		}
		else
		{
			return 1;
		}
	}
	else
	{
		STREAM_CALL(stream = pgp_stream_push(stream, key));
	}

	OS_CALL(os_seek(command.keyring, 0, SEEK_SET), printf("Unable to seek keyring"));
	OS_CALL(os_truncate(command.keyring, NULL, 0, 0), printf("Unable to trucate keyring"));

	spgp_write_pgp_packets_handle(command.keyring, stream, NULL);

	return 0;
}

void spgp_import_keys(void)
{
	pgp_error_t status = 0;

	pgp_stream_t *key_stream = NULL;
	pgp_key_packet *key = NULL;
	pgp_user_id_packet *uid = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_keyring_packet *keyring_packet = NULL;
	pgp_user_info *uinfo = NULL;

	byte_t primary_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t primary_fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	void *file = NULL;

	if (command.files != NULL)
	{
		file = command.files->packets[0];
	}

	key_stream = spgp_read_pgp_packets(file);

	key = key_stream->packets[0];
	uid = key_stream->packets[1];
	sign = key_stream->packets[2];

	PGP_CALL(pgp_key_fingerprint(key, primary_fingerprint, &primary_fingerprint_size));
	PGP_CALL(pgp_key_packet_make_definition(key, sign));

	spgp_write_key(key);

	status = pgp_verify_certificate_binding_signature(sign, key, uid);

	if (status == 1)
	{
		printf("Good Certification Signature.\n");
	}
	else
	{
		printf("Bad Certification Signature.\n");
		exit(1);
	}

	PGP_CALL(pgp_user_info_from_certificate(&uinfo, uid, sign));
	PGP_CALL(pgp_keyring_packet_new(&keyring_packet, key->version, primary_fingerprint, uinfo));

	uinfo = NULL;

	for (uint32_t i = 3; i < key_stream->count; ++i)
	{
		pgp_packet_header *header = key_stream->packets[i];
		pgp_packet_type type = pgp_packet_get_type(header->tag);

		if (type == PGP_UID)
		{
			pgp_user_id_packet *other_uid = key_stream->packets[i];

			PGP_CALL(pgp_user_info_from_certificate(&uinfo, other_uid, sign));
			PGP_CALL(pgp_keyring_packet_add_user(keyring_packet, uinfo));
		}

		if (type == PGP_PUBSUBKEY || type == PGP_SECSUBKEY)
		{
			pgp_key_packet *subkey = key_stream->packets[i];
			pgp_signature_packet *subsign = NULL;

			byte_t subkey_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
			byte_t subkey_fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

			PGP_CALL(pgp_key_fingerprint(subkey, subkey_fingerprint, &subkey_fingerprint_size));
			PGP_CALL(pgp_keyring_packet_add_subkey(keyring_packet, subkey_fingerprint));

			if ((i + 1) < key_stream->count)
			{
				subsign = key_stream->packets[i + 1];

				if (pgp_packet_get_type(subsign->header.tag) == PGP_SIG)
				{
					pgp_key_packet_make_definition(subkey, subsign);
					i += 1;
				}
			}

			spgp_write_key(subkey);

			uint32_t result = pgp_verify_subkey_binding_signature(subsign, key, subkey);

			if (result == 1)
			{
				printf("Good Subkey Binding Signature.\n");
			}
			else
			{
				printf("Bad Subkey Binding Signature.\n");
			}
		}
	}

	spgp_update_keyring(keyring_packet, SPGP_KEYRING_REPLACE);
	spgp_import_certificates(key_stream);

	pgp_keyring_packet_delete(keyring_packet);
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
			curve = "unkown";
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

	// Check if key needs decryption
	if (key->encrypted == NULL && key->encrypted_octets == 0)
	{
		return key;
	}

	PGP_CALL(pgp_key_fingerprint(key, fingerprint, &fingerprint_size));
	get_key_passphrase_env(passphrase_env, fingerprint, fingerprint_size);

	passphrase = getenv(passphrase_env);

	if (passphrase == NULL)
	{
		// Try the primary key fingerprint
		if (memcmp(fingerprint, keyring->primary_fingerprint, fingerprint_size) != 0)
		{
			get_key_passphrase_env(passphrase_env, keyring->primary_fingerprint, fingerprint_size);
			passphrase = getenv(passphrase_env);
		}

		// Prompt the user for password
		if (passphrase == NULL)
		{
			passphrase = spgp_prompt_passphrase();
		}
	}

	if (passphrase == NULL)
	{
		printf("Key passphrase not provided.\n");
		exit(1);
	}

	PGP_CALL(pgp_key_packet_decrypt(key, passphrase, strlen(passphrase)));

	return key;
}

byte_t *spgp_prompt_passphrase(void)
{
	// TODO
	return NULL;
}
