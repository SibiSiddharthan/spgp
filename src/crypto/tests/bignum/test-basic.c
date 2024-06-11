/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <string.h>
#include <bignum.h>

#include <test.h>

int32_t bignum_byte_tests(void)
{
	int32_t status = 0;
	int32_t result = 0;
	bignum_t *bn = NULL;

	byte_t buffer[64] = {0};
	byte_t bytes[20] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
						0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x15, 0x1a, 0x1e};

	// --------------------------------------------------------------------------------------

	bn = bignum_new(255);
	bn = bignum_set_bytes_le(bn, bytes, 20);

	memset(buffer, 0, 64);
	result = bignum_get_bytes_le(bn, buffer, 64);

	status += CHECK_BLOCK(buffer, 20, "000102030405060708090a0b0c0d0e0f10151a1e");
	status += CHECK_VALUE(result, 20);

	memset(buffer, 0, 64);
	result = bignum_get_bytes_be(bn, buffer, 64);

	status += CHECK_BLOCK(buffer, 20, "1e1a15100f0e0d0c0b0a09080706050403020100");
	status += CHECK_VALUE(result, 20);

	bignum_free(bn);
	bn = NULL;

	// --------------------------------------------------------------------------------------

	bn = bignum_set_bytes_be(NULL, bytes, 20);

	memset(buffer, 0, 64);
	result = bignum_get_bytes_le(bn, buffer, 64);

	status += CHECK_BLOCK(buffer, 19, "1e1a15100f0e0d0c0b0a090807060504030201");
	status += CHECK_VALUE(result, 19);

	memset(buffer, 0, 64);
	result = bignum_get_bytes_be(bn, buffer, 64);

	status += CHECK_BLOCK(buffer, 19, "0102030405060708090a0b0c0d0e0f10151a1e");
	status += CHECK_VALUE(result, 19);

	bignum_free(bn);
	bn = NULL;

	// --------------------------------------------------------------------------------------

	return status;
}

int32_t bignum_hex_tests(void)
{
	int32_t status = 0;
	int32_t result = 0;
	bignum_t *bn = NULL;

	char buffer[64] = {0};
	char *hex1 = "0x102030405060708090a0b0c0d0e0f0ffeeddccbbaa";
	char *hex2 = "-0012030405060708090A0B0C0D0E0F0FFEEDDCCBBAA";

	// --------------------------------------------------------------------------------------

	bn = bignum_new(255);
	bn = bignum_set_hex(bn, hex1, 44);

	memset(buffer, 0, 64);
	result = bignum_get_hex(bn, buffer, 64);

	status += CHECK_HEX(buffer, "0x102030405060708090a0b0c0d0e0f0ffeeddccbbaa", 44);
	status += CHECK_VALUE(result, 44);

	bignum_free(bn);
	bn = NULL;

	// --------------------------------------------------------------------------------------

	bn = bignum_set_hex(NULL, hex2, 44);

	memset(buffer, 0, 64);
	result = bignum_get_hex(bn, buffer, 64);

	// The first 00 should be trucated.
	status += CHECK_HEX(buffer, "-0x12030405060708090a0b0c0d0e0f0ffeeddccbbaa", 44);
	status += CHECK_VALUE(result, 44);

	bignum_free(bn);
	bn = NULL;

	// --------------------------------------------------------------------------------------

	return status;
}

int32_t bignum_bitcount_tests(void)
{
	int32_t status = 0;
	uint32_t bits = 0;

	bignum_t *bn = NULL;
	char *hex = "0x102030405060708090a0b0c0d0e0f0ffeeddccbbaa";

	bn = bignum_set_hex(bn, hex, 44);
	bits = bignum_bitcount(bn);

	status += CHECK_VALUE(bits, 165);

	bignum_free(bn);

	return status;
}

int main()
{
	return bignum_byte_tests() + bignum_hex_tests() + bignum_bitcount_tests();
}
