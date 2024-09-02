/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>

#include <drbg.h>

#include <test.h>

static uint32_t hmac_drbg_sha256_no_reseed_entropy(void *buffer, size_t size)
{
	static uint32_t count = 0;

	switch (count)
	{
	case 0:
		hex_to_block(buffer, 32, "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488");
		hex_to_block((byte_t *)buffer + 32, 16, "659ba96c601dc69fc902940805ec0ca8");
		break;

	default:
		break;
	}

	++count;

	return size;
}

int32_t hmac_drbg_test_suite()
{
	int32_t status = 0;
	hmac_drbg *hdrbg = NULL;

	byte_t buffer[128] = {0};

	hdrbg = hmac_drbg_new(hmac_drbg_sha256_no_reseed_entropy, HMAC_SHA256, 65536, NULL, 0);

	status += CHECK_BLOCK(hdrbg->seed, 32, "e75855f93b971ac468d200992e211960202d53cf08852ef86772d6490bfb53f9");
	status += CHECK_BLOCK(hdrbg->key, 32, "302a4aba78412ab36940f4be7b940a0c728542b8b81d95b801a57b3797f9dd6e");

	memset(buffer, 0, 128);
	hmac_drbg_generate(hdrbg, 0, NULL, 0, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 32, "bfbdcf455d5c82acafc59f339ce57126ff70b67aef910fa25db7617818faeafe");
	status += CHECK_BLOCK(hdrbg->key, 32, "911bf7cbda4387a172a1a3daf6c9fa8e17c4bfef69cc7eff1341e7eef88d2811");

	memset(buffer, 0, 128);
	hmac_drbg_generate(hdrbg, 0, NULL, 0, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107"
		"694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8");

	status += CHECK_BLOCK(hdrbg->seed, 32, "6b94e773e3469353a1ca8face76b238c5919d62a150a7dfc589ffa11c30b5b94");
	status += CHECK_BLOCK(hdrbg->key, 32, "6dd2cd5b1edba4b620d195ce26ad6845b063211d11e591432de37a3ad793f66c");

	hmac_drbg_delete(hdrbg);

	return status;
}

int main()
{
	return hmac_drbg_test_suite();
}
