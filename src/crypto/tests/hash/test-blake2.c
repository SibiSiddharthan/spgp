/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <blake2.h>
#include <test.h>

// See RFC 7693 : The BLAKE2 Cryptographic Hash and Message Authentication Code, Appendix E

static void selftest_sequence(uint8_t *out, size_t len, uint32_t seed)
{
	uint32_t t, a, b;
	a = 0xDEAD4BAD * seed; // prime
	b = 1;

	for (size_t i = 0; i < len; i++)
	{
		t = a + b;
		a = b;
		b = t;
		out[i] = (t >> 24) & 0xFF;
	}
}

static void blake2b_hash(byte_t *out, size_t outlen, void *key, size_t keylen, void *in, size_t inlen)
{
	blake2b_param param = {.digest_size = outlen, .key_size = keylen, .depth = 1, .fanout = 1};
	blake2b_ctx ctx = {0};

	blake2b_init(&ctx, &param, key);
	blake2b_update(&ctx, in, inlen);
	blake2b_final(&ctx, out, outlen);
}

static void blake2s_hash(byte_t *out, size_t outlen, void *key, size_t keylen, void *in, size_t inlen)
{
	blake2s_param param = {.digest_size = outlen, .key_size = keylen, .depth = 1, .fanout = 1};
	blake2s_ctx ctx = {0};

	blake2s_init(&ctx, &param, key);
	blake2s_update(&ctx, in, inlen);
	blake2s_final(&ctx, out, outlen);
}

int32_t blake2b_selftest()
{
	// Parameter sets
	const size_t blake2b_md_len[4] = {20, 32, 48, 64};
	const size_t blake2b_in_len[6] = {0, 3, 128, 129, 255, 1024};
	byte_t in[1024], md[64], key[64];
	blake2b_param param = {.digest_size = 32, .key_size = 0, .depth = 1, .fanout = 1};
	blake2b_ctx ctx = {0};

	// 256-bit hash for testing
	blake2b_init(&ctx, &param, NULL);

	for (size_t i = 0; i < 4; i++)
	{
		size_t outlen = blake2b_md_len[i];

		for (size_t j = 0; j < 6; j++)
		{
			size_t inlen = blake2b_in_len[j];
			selftest_sequence(in, inlen, inlen); // unkeyed hash
			blake2b_hash(md, outlen, NULL, 0, in, inlen);
			blake2b_update(&ctx, md, outlen);       // hash the hash
			selftest_sequence(key, outlen, outlen); // keyed hash
			blake2b_hash(md, outlen, key, outlen, in, inlen);
			blake2b_update(&ctx, md, outlen); // hash the hash
		}
	}

	// Compute and compare the hash of hashes
	blake2b_final(&ctx, md, 32);
	return CHECK_HASH(md, 32, "c23a7800d98123bd10f506c61e29da5603d763b8bbad2e737f5e765a7bccd475");
}

int blake2s_selftest()
{
	// Parameter sets.
	const size_t b2s_md_len[4] = {16, 20, 28, 32};
	const size_t b2s_in_len[6] = {0, 3, 64, 65, 255, 1024};
	byte_t in[1024], md[32], key[32];
	blake2s_param param = {.digest_size = 32, .key_size = 0, .depth = 1, .fanout = 1};
	blake2s_ctx ctx = {0};

	// 256-bit hash for testing.
	blake2s_init(&ctx, &param, NULL);

	for (size_t i = 0; i < 4; i++)
	{
		size_t outlen = b2s_md_len[i];
		for (size_t j = 0; j < 6; j++)
		{
			size_t inlen = b2s_in_len[j];
			selftest_sequence(in, inlen, inlen); // unkeyed hash
			blake2s_hash(md, outlen, NULL, 0, in, inlen);
			blake2s_update(&ctx, md, outlen);       // hash the hash
			selftest_sequence(key, outlen, outlen); // keyed hash
			blake2s_hash(md, outlen, key, outlen, in, inlen);
			blake2s_update(&ctx, md, outlen); // hash the hash
		}
	}

	// Compute and compare the hash of hashes.
	blake2s_final(&ctx, md, 32);
	return CHECK_HASH(md, 32, "6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe");
}

int main()
{
	return blake2b_selftest() + blake2s_selftest();
}
