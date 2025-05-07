/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_H
#define SPGP_H

#include <types.h>
#include <buffer.h>

#include <packet.h>
#include <key.h>
#include <stream.h>

#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>
#include <round.h>
#include <load.h>

#include <status.h>
#include <os.h>
#include <io.h>

// Configuration
#define SPGP_DEFAULT_HOME ".spgp"
#define SPGP_CONFIG       "spgp.conf"
#define SPGP_KEYRING      "keyring"

// Directories
#define SPGP_KEYS  "keys"
#define SPGP_CERTS "certs"

// Filename extensions
#define SPGP_KEY_EXT  ".key"
#define SPGP_CERT_EXT ".cert"

typedef enum _spgp_mode
{
	SPGP_MODE_RFC4880 = 1,
	SPGP_MODE_OPENPGP,
	SPGP_MODE_LIBREPGP,
} spgp_mode;

typedef struct _spgp_command
{
	spgp_mode mode;

	handle_t home;
	handle_t keys;
	handle_t certs;
	handle_t keyring;

	void *homedir;
	void *passhprase;

	void *output;
	void *user;
	pgp_stream_t *files;
	pgp_stream_t *users;
	pgp_stream_t *recipients;

	time_t timestamp;
	byte_t need_home;
	byte_t stateless;

	byte_t cipher_algorithm;
	byte_t hash_algorithm;
	byte_t compression_algorithm;

	union
	{
		struct
		{
			byte_t armor : 1;
			byte_t dearmor : 1;

			byte_t sign : 1;
			byte_t detach_sign : 1;
			byte_t clear_sign : 1;
			byte_t verify : 1;

			byte_t encrypt : 1;
			byte_t symmetric : 1;
			byte_t decrypt : 1;

			byte_t import_keys : 1;
			byte_t export_keys : 1;
			byte_t export_secret_keys : 1;

			byte_t delete_keys : 1;
			byte_t delete_secret_keys : 1;

			byte_t list_keys : 1;
			byte_t list_secret_keys : 1;

			byte_t generate_key : 1;
			byte_t full_generate_key : 1;

			byte_t list_packets : 1;
			byte_t dump_packets : 1;
			byte_t no_print_mpis : 1;
		};

		uint64_t options;
	};

} spgp_command;

extern spgp_command command;

uint32_t spgp_generate_key(void);
uint32_t spgp_delete_key(const char *key_id, uint16_t key_id_size, uint32_t options);

uint32_t spgp_export_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size);
uint32_t spgp_import_key(void *buffer, size_t buffer_size);

uint32_t spgp_search_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size, uint32_t options);

uint32_t spgp_sign(spgp_command *command);
uint32_t spgp_verify(spgp_command *command);

uint32_t spgp_encrypt(spgp_command *command);
uint32_t spgp_decrypt(spgp_command *command);

uint32_t spgp_list_keys(void);
uint32_t spgp_list_packets(spgp_command *command);

uint32_t spgp_import_keys(spgp_command *command);
uint32_t spgp_export_keys(spgp_command *command);
uint32_t spgp_delete_keys(spgp_command *command);

#define SPGP_STD_INPUT  0x1
#define SPGP_STD_OUTPUT 0x2

pgp_literal_packet *spgp_read_file_as_literal(const char *file, pgp_literal_data_format format);

void *spgp_read_file(const char *file, uint32_t options, size_t *size);
size_t spgp_write_file(const char *file, uint32_t options, void *buffer, size_t size);

status_t spgp_read_handle(handle_t handle, void **buffer, size_t *size);
size_t spgp_write_handle(handle_t handle, void *buffer, size_t size);

pgp_stream_t *spgp_read_pgp_packets(const char *file, uint32_t options);
void *spgp_read_pgp_packet(const char *file, uint32_t options);

pgp_stream_t *spgp_read_pgp_packets_from_handle(handle_t handle);
void *spgp_read_pgp_packet_from_handle(handle_t handle);
size_t spgp_write_pgp_packets_to_handle(handle_t handle, pgp_stream_t *stream);
size_t spgp_write_pgp_packet_to_handle(handle_t handle, void *packet);

size_t spgp_write_pgp_packets(const char *file, uint32_t options, pgp_stream_t *stream);
size_t spgp_write_pgp_packet(const char *file, uint32_t options, void *packet);

pgp_key_packet *spgp_read_key(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size);
void spgp_write_key(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size, pgp_key_packet *packet);

pgp_stream_t *spgp_read_certificate(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size);
size_t spgp_write_certificate(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size, pgp_stream_t *stream);

#define SPGP_KEYRING_REPLACE 0x1

pgp_stream_t *spgp_read_keyring();
pgp_keyring_packet *spgp_search_keyring(pgp_key_packet **key, pgp_user_info **user, void *input, uint32_t size, byte_t capabilities);
uint32_t spgp_update_keyring(pgp_keyring_packet *key, uint32_t options);

#endif
