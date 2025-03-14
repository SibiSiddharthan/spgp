/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <spgp.h>
#include <algorithms.h>
#include <argparse.h>
#include <packet.h>
#include <stream.h>
#include <key.h>
#include <session.h>
#include <seipd.h>
#include <signature.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *version = "\
sgpg 0.1\n\
Copyright (c) 2024 - 2025 Sibi Siddharthan\n\
Distributed under the MIT license\n\
\n\
Supported algorithms:\n\
Public Key: RSA, DSA, ECDH, ECDSA, EDDSA, ED25519, ED448, X25519, X448\n\
Symmetric Ciphers: TDES, AES, CAMELLIA, TWOFISH\n\
Hash: MD5, RIPEMD160, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-256, SHA3-512\n\
Compression: Uncompressed\n\
";

static const char *help = "\
Usage: sgpg [options] [files]\n\
Sign, Verify, Encrypt or Decrypt\n\
\n\
Basic Commands:\n\
\n\
 -s, --sign                     make a signature\n\
     --clear-sign               make a clear text signature\n\
 -b, --detach-sign              make a detached signature\n\
 -e, --encrypt                  encrypt data\n\
 -c, --symmetric                encryption only with symmetric cipher\n\
 -d, --decrypt                  decrypt data\n\
     --verify                   verify a signature\n\
 -a, --armor                    create ascii armored output\n\
     --dearmor                  create pgp packet output (default)\n\
\n\
Key Commands:\n\
\n\
 -k, --list-keys                list keys\n\
     --list-signatures          list keys and signatures\n\
     --check-signatures         list and check key signatures\n\
     --fingerprint              list keys and fingerprints\n\
 -K, --list-secret-keys         list secret keys\n\
     --generate-key             generate a new key pair\n\
     --full-generate-key        full featured key pair generation\n\
     --generate-revocation      generate a revocation certificate\n\
     --delete-keys              remove keys from the public keyring\n\
     --delete-secret-keys       remove keys from the secret keyring\n\
     --sign-key                 sign a key\n\
     --edit-key                 sign or edit a key\n\
     --export                   export keys\n\
     --export-secret-keys       export secret keys\n\
     --import                   import/merge keys\n\
     --import-secret-keys       import/merge secret keys\n\
     --change-passphrase        change a passphrase\n\
     --send-keys                export keys to a keyserver\n\
     --receive-keys             import keys from a keyserver\n\
     --search-keys              search for keys on a keyserver\n\
     --refresh-keys             update all keys from a keyserver\n\
\n\
Packet Commands:\n\
     --list-packets             list PGP packets\n\
     --dump-packets             dump PGP packets\n\
\n\
Miscellaneous Commands:\n\
     -h, --help                 help\n\
     --version                  print SPGP version information\n\
\n\
Output Options:\n\
\n\
 -v, --verbose                  verbose\n\
 -q, --quiet                    quiet\n\
 -o, --output FILE              write output to FILE\n\
 -z  --compress-level N         compression level to N (0 disables)\n\
\n\
Key Selection:\n\
 -r, --recipient USER-ID        encrypt for USER-ID\n\
 -u, --local-user USER-ID       use USER-ID to sign or decrypt\n\
\n\
Algorithm Options:\n\
     --digest-algo ALGO         hash using ALGO\n\
     --cipher-algo ALGO         encrypt using ALGO\n\
     --compress-algo ALGO       compress using ALGO\n\
\n\
Operation Modes:\n\
     --rfc4880                  conform to rfc 4880 specification\n\
     --openpgp                  conform to openpgp specification\n\
     --librepgp                 conform to librepgp specification\n\
\n\
Miscellaneous Options:\n\
 -n, --dry-run                  dry run (no modifications)\n\
 -i, --interactive              prompt before overwriting\n\
     --batch                    enable batch mode\n\
     --expert                   enable expert mode\n\
     --homedir                  set home directory for spgp\n\
     --passphrase PS            use passphrase PS\n\
     --faked-system-time TIME   use timestamp TIME\n\
\n\
";

typedef enum _spgp_option
{
	// Basic Commands
	SPGP_SIGN = 1,
	SPGP_DETACH_SIGN,
	SPGP_CLEAR_SIGN,
	SPGP_VERIFY,
	SPGP_SYMMETRIC_ENCRYPT,
	SPGP_ENCRYPT,
	SPGP_DECRYPT,
	SPGP_ARMOR,
	SPGP_DEARMOR,

	// Key Commands
	SPGP_LIST_KEYS,
	SPGP_LIST_SECRET_KEYS,
	SPGP_DELETE_KEYS,
	SPGP_DELETE_SECRET_KEYS,
	SPGP_EXPORT_KEYS,
	SPGP_EXPORT_SECRET_KEYS,
	SPGP_IMPORT_KEYS,
	SPGP_IMPORT_SECRET_KEYS,
	SPGP_GENERATE_ROVOCATION,
	SPGP_GENERATE_KEY,
	SPGP_FULL_GENERATE_KEY,

	// Packet Commands
	SPGP_LIST_PACKETS,
	SPGP_DUMP_PACKETS,

	// Miscellaneous Commands
	SPGP_HELP,
	SPGP_VERSION,

	// Output Options
	SPGP_VERBOSE,
	SPGP_QUIET,
	SPGP_OUTPUT,
	SPGP_COMPRESS_LEVEL,

	// Key Selection
	SPGP_RECIPIENT,
	SPGP_USER_ID,

	// Algorithm Options
	SPGP_DIGEST_ALGORITHM,
	SPGP_CIPHER_ALGORITHM,
	SPGP_COMPRESS_ALGORITHM,

	// Operation Modes
	SPGP_RFC4880,
	SPGP_OPENPGP,
	SPGP_LIBREPGP,

	// Miscellaneous Options
	SPGP_DRY_RUN,
	SPGP_INTERACTIVE,
	SPGP_BATCH,
	SPGP_EXPERT,
	SPGP_HOMEDIR,
	SPGP_PASSPHRASE,
	SPGP_FAKED_TIME,
} spgp_option;

static arg_option_t spgp_options[] = {
	// Basic Commands
	{"sign", 's', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_SIGN},
	{"detach-sign", 'b', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DETACH_SIGN},
	{"clear-sign", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_CLEAR_SIGN},
	{"verify", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_VERIFY},
	{"symmetric", 'c', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_SYMMETRIC_ENCRYPT},
	{"encrypt", 'e', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_ENCRYPT},
	{"decrypt", 'd', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DECRYPT},
	{"armor", 'a', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_ARMOR},
	{"dearmor", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DEARMOR},

	// Key Commands
	{"list-keys", 'k', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_LIST_KEYS},
	{"list-secret-keys", 'K', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_LIST_SECRET_KEYS},
	{"delete-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DELETE_KEYS},
	{"delete-secret-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DELETE_SECRET_KEYS},
	{"export-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_EXPORT_KEYS},
	{"export-secret-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_EXPORT_SECRET_KEYS},
	{"import-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_IMPORT_KEYS},
	{"import-secret-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_IMPORT_SECRET_KEYS},
	{"generate-revocation", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_GENERATE_ROVOCATION},
	{"generate-key", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_GENERATE_KEY},
	{"full-generate-key", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_FULL_GENERATE_KEY},

	// Packet Commands
	{"list-packets", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_LIST_PACKETS},
	{"dump-packets", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DUMP_PACKETS},

	// Miscellaneous Commands
	{"help", 'h', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_HELP},
	{"version", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_VERSION},

	// Output Options
	{"verbose", 'v', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_VERBOSE},
	{"quiet", 'q', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_QUIET},
	{"output", 'o', ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OUTPUT},
	{"compress-level", 'z', ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_COMPRESS_LEVEL},

	// Key Selection
	{"recipient", 'r', ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_RECIPIENT},
	{"local-user", 'u', ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_USER_ID},

	// Algorithm Options
	{"digest-algo", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_DIGEST_ALGORITHM},
	{"cipher-algo", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_CIPHER_ALGORITHM},
	{"compress-algo", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_COMPRESS_ALGORITHM},

	// Operation Modes
	{"rfc4880", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_RFC4880},
	{"openpgp", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPENPGP},
	{"librepgp", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_LIBREPGP},

	// Miscellaneous Options
	{"dry-run", 'n', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DRY_RUN},
	{"interactive", 'i', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_INTERACTIVE},
	{"batch", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_BATCH},
	{"expert", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_EXPERT},
	{"homedir", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_HOMEDIR},
	{"passphrase", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_PASSPHRASE},
	{"faked-system-time", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_FAKED_TIME}

	// Compatibility Options
};

static void spgp_print_help()
{
	printf("%s", help);
}

static void spgp_list_packets(char *file)
{
	char buffer[65536] = {0};
	char str[65536] = {0};

	size_t size = 0;

	FILE *f = fopen(file, "rb");
	size = fread(buffer, 1, 65536, f);

	fclose(f);

	pgp_stream_t *stream = pgp_stream_read(buffer, size);
	pgp_stream_print(stream, str, 65536, PGP_PRINT_HEADER_ONLY);

	printf("%s", str);
}

static void spgp_dump_packets(char *file)
{
	char buffer[65536] = {0};
	char str[65536] = {0};

	size_t size = 0;

	FILE *f = fopen(file, "rb");
	size = fread(buffer, 1, 65536, f);

	fclose(f);

	pgp_stream_t *stream = pgp_stream_read(buffer, size);
	pgp_stream_print(stream, str, 65536, 0);

	printf("%s", str);
}

int main(int argc, char **argv)
{
	argparse_t *actx =
		argparse_new(argc, (void **)argv, sizeof(spgp_options) / sizeof(arg_option_t), spgp_options, ARGPARSE_FLAG_SKIP_FIRST_ARGUMENT);
	arg_result_t *result = NULL;

	while ((result = argparse(actx, 0)) != NULL)
	{
		switch (result->value)
		{
		case SPGP_HELP:
		{
			spgp_print_help();
		}
		break;
		case SPGP_LIST_PACKETS:
		{
			spgp_list_packets(result->data);
		}
		break;
		case SPGP_DUMP_PACKETS:
		{
			spgp_dump_packets(result->data);
		}
		break;
		}
	}

	return 0;
}
