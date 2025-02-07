/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <spgp.h>
#include <packet.h>

#include <stdio.h>
#include <stdlib.h>

const char *help = 
"\
Usage: sgpg [options] [files]\
Sign, Verify, Encrypt or Decrypt\
\
Commands:\
\
 -s, --sign                     make a signature\
     --clear-sign               make a clear text signature\
 -b, --detach-sign              make a detached signature\
 -e, --encrypt                  encrypt data\
 -c, --symmetric                encryption only with symmetric cipher\
 -d, --decrypt                  decrypt data (default)\
     --verify                   verify a signature\
 -k, --list-keys                list keys\
     --list-signatures          list keys and signatures\
     --check-signatures         list and check key signatures\
     --fingerprint              list keys and fingerprints\
 -K, --list-secret-keys         list secret keys\
     --generate-key             generate a new key pair\
     --full-generate-key        full featured key pair generation\
     --generate-revocation      generate a revocation certificate\
     --delete-keys              remove keys from the public keyring\
     --delete-secret-keys       remove keys from the secret keyring\
     --sign-key                 sign a key\
     --edit-key                 sign or edit a key\
     --export                   export keys\
     --import                   import/merge keys\
     --change-passphrase        change a passphrase\
     --send-keys                export keys to a keyserver\
     --receive-keys             import keys from a keyserver\
     --search-keys              search for keys on a keyserver\
     --refresh-keys             update all keys from a keyserver\
\
Options:\
 -v, --verbose                  verbose\
 -q, --quiet                    quiet\
 -h, --help                     help\
 -n, --dry-run                  dry run (no modifications)\
 -i, --interactive              prompt before overwriting\
 -a, --armor                    create ascii armored output\
 -o, --output FILE              write output to FILE\
     --textmode                 use canonical text mode\
 -z N                           compression level to N (0 disables)\
\
Keys:\
 -r, --recipient USER-ID        encrypt for USER-ID\
 -u, --local-user USER-ID       use USER-ID to sign or decrypt\
\
Packets:\
     --list-packets             List PGP packets\
     --dump-packets             Dump PGP packets\
\
";

int main(int argc, char **argv)
{
	char buffer[65536];
	size_t size = 0;

	for (int i = 1; i < argc; ++i)
	{
		FILE *file = fopen(argv[i], "rb");

		if (file == NULL)
		{
			printf("%s not found.\n", argv[i]);
			break;
		}

		size = fread(buffer, 1, 65536, file);
		fclose(file);
	}

	return 0;
}
