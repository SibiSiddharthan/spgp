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

static const char *help = "\n\
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
     --textmode                 use canonical text mode\n\
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
	// Commands
	SPGP_SIGN = 1,
	SPGP_DETACH_SIGN,
	SPGP_CLEAR_SIGN,
	SPGP_VERIFY,
	SPGP_SYMMETRIC_ENCRYPT,
	SPGP_ENCRYPT,
	SPGP_DECRYPT,
	SPGP_LIST_KEYS,
	SPGP_LIST_SECRET_KEYS,
	SPGP_DELETE_KEYS,
	SPGP_DELETE_SECRET_KEYS,
	SPGP_ARMOR,
	SPGP_DEARMOR,
	SPGP_VERBOSE,
	SPGP_QUIET,
	SPGP_HELP,
	SPGP_VERSION,
	SPGP_OUTPUT,
	SPGP_LIST_PACKETS,
	SPGP_DUMP_PACKETS,
} spgp_option;

static arg_option_t spgp_options[] = {
	{"sign", 's', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_SIGN},
	{"detach-sign", 'b', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DETACH_SIGN},
	{"clear-sign", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_CLEAR_SIGN},
	{"verify", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_VERIFY},
	{"symmetric", 'c', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_SYMMETRIC_ENCRYPT},
	{"encrypt", 'e', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_ENCRYPT},
	{"decrypt", 'd', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DECRYPT},
	{"list-keys", 'k', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_LIST_KEYS},
	{"list-secret-keys", 'K', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_LIST_SECRET_KEYS},
	{"delete-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DELETE_KEYS},
	{"delete-secret-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DELETE_SECRET_KEYS},
	{"armor", 'a', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_ARMOR},
	{"dearmor", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DEARMOR},
	{"help", 'h', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_HELP},
	{"list-packets", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_LIST_PACKETS},
	{"dump-packets", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DUMP_PACKETS},
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
