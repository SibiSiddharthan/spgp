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

typedef enum _spgp_key_id
{
	SPGP_UNKNOWN = 0,

	// RSA
	SPGP_RSA2048,
	SPGP_RSA3072,
	SPGP_RSA4096,

	// DSA
	SPGP_DSA1024,
	SPGP_DSA2048,
	SPGP_DSA3072,

	// Elgamal
	SPGP_ELGAMAL1024,
	SPGP_ELGAMAL2048,
	SPGP_ELGAMAL3072,
	SPGP_ELGAMAL4096,

	// ECC
	SPGP_EC_NISTP256,
	SPGP_EC_NISTP384,
	SPGP_EC_NISTP521,
	SPGP_EC_BRAINPOOL256R1,
	SPGP_EC_BRAINPOOL384R1,
	SPGP_EC_BRAINPOOL512R1,
	SPGP_EC_CURVE25519,
	SPGP_EC_CURVE448,
	SPGP_EC_ED25519,
	SPGP_EC_ED448,

	// Legacy
	SPGP_EC_CURVE25519_LEGACY,
	SPGP_EC_ED25519_LEGACY,

} spgp_key_id;

typedef enum _spgp_mode
{
	SPGP_MODE_RFC4880 = 1,
	SPGP_MODE_OPENPGP,
	SPGP_MODE_LIBREPGP,
} spgp_mode;

typedef enum _spgp_operation
{
	// Reserved Command
	SPGP_OPERATION_NONE = 0,

	// Basic Commands
	SPGP_OPERATION_SIGN,
	SPGP_OPERATION_VERIFY,

	SPGP_OPERATION_ENCRYPT,
	SPGP_OPERATION_DECRYPT,

	SPGP_OPERATION_ARMOR,
	SPGP_OPERATION_DEARMOR,

	// Key Commands
	SPGP_OPERATION_LIST_KEYS,
	SPGP_OPERATION_DELETE_KEYS,
	SPGP_OPERATION_EXPORT_KEYS,
	SPGP_OPERATION_IMPORT_KEYS,
	SPGP_OPERATION_GENERATE_ROVOCATION,
	SPGP_OPERATION_GENERATE_KEY,

	// Packet Commands
	SPGP_OPERATION_LIST_PACKETS
} spgp_operation;

typedef struct _spgp_command
{
	spgp_operation operation;
	spgp_mode mode;

	handle_t home;
	handle_t keys;
	handle_t certs;
	handle_t keyring;

	void *homedir;
	void *passhprase;

	void *output;
	void *user;
	pgp_stream_t *users;
	pgp_stream_t *recipients;

	time_t timestamp;
	byte_t cipher_algorithm;
	byte_t hash_algorithm;
	byte_t compression_algorithm;

	byte_t armor : 1;
	byte_t dearmor : 1;

#if 0
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

	byte_t list_keys : 1;
	byte_t list_secret_keys : 1;

	byte_t generate_key : 1;
	byte_t full_generate_key : 1;

	byte_t list_packets : 1;
	byte_t dump_packets : 1;
#endif

	union
	{
		struct
		{
			byte_t detach;
			byte_t cleartext;
			char *file;
		} sign;

		struct
		{
			char *sign;
			char *file;
		} verify;

		struct
		{
			byte_t symmetric;
			char *file;
		} encrypt;

		struct
		{
			char *file;
		} decrypt;

		struct
		{
			char *file;
		} import;

		struct
		{
			byte_t secret;
			char *key;
		} export;

		struct
		{
			char *key;
		} delete;

		struct
		{
			byte_t secret;
		} list_keys;

		struct
		{
			byte_t dump;
			byte_t no_mpi;
			char *file;
		} list_packets;
	};

} spgp_command;

extern spgp_command command;

uint32_t spgp_generate_key(spgp_key_id id, const char *uid, uint16_t uid_size);
uint32_t spgp_delete_key(const char *key_id, uint16_t key_id_size, uint32_t options);

uint32_t spgp_export_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size);
uint32_t spgp_import_key(void *buffer, size_t buffer_size);

uint32_t spgp_search_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size, uint32_t options);

uint32_t spgp_sign(spgp_command *command);
uint32_t spgp_verify(spgp_command *command);

uint32_t spgp_encrypt(spgp_command *command);
uint32_t spgp_decrypt(spgp_command *command);

uint32_t spgp_list_keys(spgp_command *command);
uint32_t spgp_list_packets(spgp_command *command);

uint32_t spgp_import_keys(spgp_command *command);
uint32_t spgp_export_keys(spgp_command *command);
uint32_t spgp_delete_keys(spgp_command *command);

#define SPGP_STD_INPUT  0x1
#define SPGP_STD_OUTPUT 0x2

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
pgp_keyring_packet *spgp_search_keyring();
uint32_t spgp_update_keyring(pgp_keyring_packet *key, uint32_t options);

#endif
