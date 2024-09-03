/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <string.h>

#include <drbg.h>
#include <test.h>

// Tests taken from NIST

static uint32_t hmac_drbg_sha256_entropy(void *buffer, size_t size)
{
	static uint32_t count = 0;

	switch (count)
	{
	case 0:
		hex_to_block(buffer, 32, "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488");
		hex_to_block((byte_t *)buffer + 32, 16, "659ba96c601dc69fc902940805ec0ca8");
		break;
	case 1:
		hex_to_block(buffer, 32, "f074a8cf417a9a4c4aade25f530567fd7a1410a074f3b0edd664bbc430ddb250");
		hex_to_block((byte_t *)buffer + 32, 16, "d3c0823b6d28a42d5f0fc01496d32859");
		break;
	case 2:
		hex_to_block(buffer, 32, "00efb9c7f02719ff5c7030ffa897a308d36c11ce27526340728bcd487c80457b");
		hex_to_block((byte_t *)buffer + 32, 16, "09cebd489d363b5578ddf30534ee6a7f");
		break;
	case 3:
		hex_to_block(buffer, 32, "4c87234a9bb529aebb7278daa089753bd2b501d30677edb6cc31e38788fe0e21");
		break;
	case 4:
		hex_to_block(buffer, 32, "4b7e3f8a5f270aa2386dc1c1cf00c6dbddbd49f9911c0cb3f14f91ffe23f71f5");
		hex_to_block((byte_t *)buffer + 32, 16, "4536ed125240aa60cb3a255ef0e307a0");
		break;
	case 5:
		hex_to_block(buffer, 32, "cf064f20b82f991ccec2381aecb0caae50c7b6407f8c76784d42a5af09c06290");
		break;
	case 6:
		hex_to_block(buffer, 32, "3cd4ce3f5dc941836afa0388c959b0d3783764f288296ac66960c28a7be1f75f");
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
	byte_t extra[32] = {0};

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Simple

	hdrbg = hmac_drbg_new(hmac_drbg_sha256_entropy, HMAC_SHA256, 65536, NULL, 0);

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

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Additional inputs

	hex_to_block(extra, 32, "972527fe90601de9d13a050c7e49d556d0de6b0e75e0619807ade2178eefe47d");

	hdrbg = hmac_drbg_new(hmac_drbg_sha256_entropy, HMAC_SHA256, 65536, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 32, "0369222ee2c0a271fed4629e6954613f8b96a19174eaf6bace11822ef8a0db01");
	status += CHECK_BLOCK(hdrbg->key, 32, "fc24c5b12d7ead3a43c84ebf38c3ddede2b6691bf5aecd5bcd75afa4a205620f");

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "0dc678372c9f24230d15acd1d36b13294c58b76f2847397fbc32dfada12b8e51");

	hmac_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 32, "0e4aa4aeca304d1918e7c92dba0eaf92f8c348ecc031ab9efa75232448133066");
	status += CHECK_BLOCK(hdrbg->key, 32, "26b7fa53a19ef63898ed51cfe9bbb9cf48ef26047a24d491cfabaa85ee83ad96");

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "59874caea33944638e1e11fa3626fa2bc26d4502120c17e0e198d04f9ef0ff95");
	hmac_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"79db15ff50059ce58dcd44553f5cb6a19554cf35d2b64c869336a797cef93b24c64b716aaa11cd82dca0143279ed7cb2698d7cd726241ca17b5ce6831b08ae84dd"
		"57f95b11c07f7fef1d381eb0b7fd535b902ccede73538155f30100fd13ff007806b367f5032561338a92541f441725eab17996dd58e9870025d98b4752b547");
	status += CHECK_BLOCK(hdrbg->seed, 32, "93a426a8cb14dd95d443cd301eb94e7c4c365740797b2f2853adb7dbd6de9dd3");
	status += CHECK_BLOCK(hdrbg->key, 32, "b559747acecd08edf539dd2e4f5465ecb0dee108181d15781015e482bb7ff958");

	hmac_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Reseed

	hex_to_block(extra, 32, "27e38c624a8f934e931e195a0cbcf38e4e8d50108dc318743fb4b61cf78a7d14");

	hdrbg = hmac_drbg_new(hmac_drbg_sha256_entropy, HMAC_SHA256, 65536, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 32, "65ee4461fd700036721800d2a71f5110cc8099fe447d4b68f317b821983a2063");
	status += CHECK_BLOCK(hdrbg->key, 32, "ac0e155af29e01caf36f5f36944adf9cef01b18a4a7aa5af8d63cd56a1d03d43");

	hex_to_block(extra, 32, "0e4dddbe0034180b59303d527a938a447bad9e4a91787d1072e6f41350ff11e5");
	hmac_drbg_reseed(hdrbg, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 32, "1de6328fc0c04353018c24e671c0828229d2bdb2faf331a9cb6363a68baf0ad9");
	status += CHECK_BLOCK(hdrbg->key, 32, "e21c915e4af5e628b7a45d2953dd61b552f256a215dd604a56067829bd4dfabe");

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "cb25fccf929812b9fc66aea93e0cafb064e25b8c2989ae5078648ef529ecb487");
	hmac_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 32, "a3d029a688de1596b7a214af9f547d26e0d03bf3f62a5755e5288923b851c02e");
	status += CHECK_BLOCK(hdrbg->key, 32, "41b4ab280425b8e79e25011bcfeef18fbfa57b272100351a742afcabb5be78cf");

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "c1685a422e4a0673cea9948937a8fdaa77777066f501aa17493682a83d931e6a");
	hmac_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"7569ff1ad01a56ab283c1f2357bd519e15c0be84b80cfe8ec6e26cf903aa8a17f52311a2458e48468122ce1f4abff12920f7dffa86c46f06d744d198004bdd0b29"
		"b1b0f17712863df82406e2c2a2fb73ea99dc3969c7e52aeaea031e0112fbf8d785426ae7c106d876a900ba54c4e9a1f3656990571c6d1fb56131cd1cdb1e68");
	status += CHECK_BLOCK(hdrbg->seed, 32, "53243974490ced473f3bc498415b40d75b08cd275bc596e5572aa14b9b51e054");
	status += CHECK_BLOCK(hdrbg->key, 32, "8d5ed0295e15688a8f9d7556fd452d63c6b0dff43e653b607cc79958cb305921");

	hmac_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Prediction resistance

	hex_to_block(extra, 32, "f293dc63e6e0dcb94bb19929a7935ec71bf16c55258eb66c63ff6d3225a8c270");

	hdrbg = hmac_drbg_new(hmac_drbg_sha256_entropy, HMAC_SHA256, 65536, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 32, "af2a826550a0482185b35501838dd3b5d7673f92407559884c8a07389bc8a2d9");
	status += CHECK_BLOCK(hdrbg->key, 32, "709931023cb2c21917a43b9f8945932d0e5c0484d1f4164c8d44046e28d8aecd");

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "4df6f301c1f2831f18ab0715706fc1e381c1c09a11ffc9af9938bd28a6fe700b");
	hmac_drbg_generate(hdrbg, 1, extra, 32, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 32, "f534194e68446e435954f03505b2bda9bdc7a00a836569944adff7abce96aacc");
	status += CHECK_BLOCK(hdrbg->key, 32, "8a2a3dd2f103aabee005bf3c53e017e42be31ced003728df50e3ce9e950fb7d4");

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "e350cc55cd96ad56aeb81b7b735dc87d48a1a8adca68e3ff0304e9438c00b776");
	hmac_drbg_generate(hdrbg, 1, extra, 32, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"a273235f5ec7b38d81fb2ac46a81b9aca8badc379a152bbbbd20fe10d58e55f8123e9909927a628304ad8d582a208b605798ab5a21877f8f9838f3d926764efb63"
		"e5eb3033f977ec816c1d462fb0c567e1e8fb029c80e0ddc0ce28a9ff311eebf1689060de7f1060cc59a818d6ddefe9e638f2bf84464d17939eace387b25f24");
	status += CHECK_BLOCK(hdrbg->seed, 32, "79f8da67e45e77a6e4f9ac8c3531da401847acb20a2c00e860df5e9f906c0ef6");
	status += CHECK_BLOCK(hdrbg->key, 32, "389b1375ed6f58da09cbae6f110a0c055d307a593e666aca262b46ac13524e18");

	hmac_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return hmac_drbg_test_suite();
}
