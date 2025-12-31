/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <string.h>
#include <bignum.h>

#include <test.h>

int32_t bignum_prime_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *k = NULL;

	// ------------------------------------------------------------------------

	k = bignum_set_hex(
		NULL,
		"e021757c777288dacfe67cb2e59dc02c70a8cebf56262336592c18dcf466e0a4ed405318ac406bd79eca29183901a557db556dd06f7c6bea175dcb8460b6b1bc05"
		"832b01eedf86463238b7cb6643deef66bc4f57bf8ff7ec7c4b8a8af14f478980aabedd42afa530ca47849f0151b7736aa4cd2ff37f322a9034de791ebe3f51",
		256);

	result = bignum_is_probable_prime(NULL, k);
	status += CHECK_VALUE(result, 1);

	bignum_delete(k);

	// ------------------------------------------------------------------------

	k = bignum_set_hex(
		NULL,
		"c0ef0f196921eea05721308d4edca39afd20d0dbd6c6c446571f69d6c873838558c8bd2e3a5bee4b7d32de9819caf9f07d3807a16616081275263789adb5c1d092"
		"f9d0001486fde649998d15650b1e442e0076cacf5b276d6d52cbbe1ec713237ff0f59460967515914aed67eb806e92bc9a0affb27de9c5c74fa9aefa357627",
		256);

	result = bignum_is_probable_prime(NULL, k);
	status += CHECK_VALUE(result, 1);

	bignum_delete(k);

	// ------------------------------------------------------------------------

	k = bignum_set_hex(
		NULL,
		"bdb4a50991c2d6cf2aeaef86068a026f1a45463697c23f7567c0cbfc5da5bc7b0b70d6e44da33df2e6bca8152292a3c6b776ea2e9f6528ea5d3e74afc19ee271ca"
		"940c2bcde6f18bf20c068bb973387d681b12d3689606825987d7bfc241cea0741a1be3a253f83e1654062db92b85287be8b385488a0eae13a4fe497d4fe751d588"
		"d0839086d1b935bf70bf715c34f87ed54cba51300aaaf53bdea5288726c7527a028dc2acf8962826a99ede37fad7b7310a77afb2bb8d9306350dc758930f",
		384);

	result = bignum_is_probable_prime(NULL, k);
	status += CHECK_VALUE(result, 1);

	bignum_delete(k);

	// ------------------------------------------------------------------------

	k = bignum_set_hex(
		NULL,
		"c23121afc2530f01528bdf680d6d718f4719792d6137ef4500ea7bf993209c6d324999d668359953c71f8b320ea02af9d4b0f5199c2fef7ccda71f507cafd83d02"
		"183fd1575815d41eca6a2cec39104e9209ccbe0800a8c277077a27e726d73c2a0b6834313d0dc7a749c036d1edaafb48dd2a80ec191446b8958ba5e42d2b642420"
		"3ea26dc60e6c8397e605398c1e7da441c0ab142a29601bda839e8d69fe037115a2c712910a56beb9b19b938215cecf4e339f05b76059041568016fe64851",
		384);

	result = bignum_is_probable_prime(NULL, k);
	status += CHECK_VALUE(result, 1);

	bignum_delete(k);

	// ------------------------------------------------------------------------

	k = bignum_set_hex(
		NULL,
		"cc356b9daab6d58f49a533d0d8cae664826a9e53817c9c11150896dd5ccbcd3667699353fc50d9d0b86c52216f8e5fd0fece69fb509c34bdf1f44aa2571fab3668"
		"3834783edc1868a93c7443149b9d0357d0b843eb517992731678a0a2cea4945c7934b7539122545185468474db8ea1c6f009f87e36e5dd189f3c8493c8b051",
		256);

	result = bignum_is_probable_prime(NULL, k);
	status += CHECK_VALUE(result, 0);

	bignum_delete(k);

	// ------------------------------------------------------------------------

	k = bignum_set_hex(
		NULL,
		"f0bebaf7930f2a789bcd082bd3928f25f4e8d650876d1261dcbeca5d8e987499b44dce2f51f667802a62e8534b9d8b847790d2cafa576cd5b1fcdd72cb949639b9"
		"1a81fb7208c1dda2a6632b61cee1a2cea1bd25f3ee5c0feb21e2449d8c91c1ca9ca951159684fe949a4a6ac1dcf73f80682132d16d48a54251cd470899bd79",
		256);

	result = bignum_is_probable_prime(NULL, k);
	status += CHECK_VALUE(result, 0);

	bignum_delete(k);

	// ------------------------------------------------------------------------

	k = bignum_set_hex(
		NULL,
		"f4d371abe9ac8db32d1ef56f50509ef00684df5d8effef2abb10907cd6115e2c851cfa99c5188915cba539453b91cdc59ebb0c69cfe8aca8a13f55333ab72cbf50"
		"4b2a7b245d876321e573a0da7e7aa682a3c1e0a363e166410d12e4d89d1714744781728e11e675e38d9c3fe62bd19dc627592cab91abb1d4f92ab9c94e222d279f"
		"12c2f2a70c91321dbe458c9bae927d51e0063d8ee8e2db38a901da3d8a3e45694e4a0e67bdfc0b9ab9bfeec66061c87a767de4b3a902de6e9059f523839f",
		384);

	result = bignum_is_probable_prime(NULL, k);
	status += CHECK_VALUE(result, 0);

	bignum_delete(k);

	// ------------------------------------------------------------------------

	k = bignum_set_hex(
		NULL,
		"e004f5a84bd1d7068590d6bd99fafbce74b118c06822e8731ea65d84fdaa6a50dbab9c016f1bd3a89588d4b5ad40cd2919263d8c91dfc906ac952b5ea915c2d25f"
		"4608dae794c87c3691b10394840e382f2712d67370c53271a2e14378e5ccb7d1c266e0a18c70dc03af850d25429a9ce72eae14d3e4d73cd0fcefb2fed74d4b7ce2"
		"911e5ae7fe053c92d251b961006bb06353dc4c717841b20141b795735be292018df45723b86df93a7e80e58f68491e9bfc6164a410f6ac439066c9dab8ab",
		384);

	result = bignum_is_probable_prime(NULL, k);
	status += CHECK_VALUE(result, 0);

	bignum_delete(k);

	// ------------------------------------------------------------------------

	return status;
}

int main()
{
	return bignum_prime_tests();
}
