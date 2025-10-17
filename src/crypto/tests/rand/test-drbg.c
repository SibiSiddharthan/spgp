/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <drbg.h>
#include <test.h>
#include <unused.h>

// Tests taken from NIST

static uint32_t hmac_drbg_sha256_entropy(void *state, void *buffer, uint32_t size)
{
	static uint32_t count = 0;

	UNUSED(state);

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

	hdrbg = hmac_drbg_new(hmac_drbg_sha256_entropy, HASH_SHA256, 65536, NULL, 0);

	status += CHECK_BLOCK(hdrbg->seed, 32, "e75855f93b971ac468d200992e211960202d53cf08852ef86772d6490bfb53f9");
	status += CHECK_BLOCK(hdrbg->key, 32, "302a4aba78412ab36940f4be7b940a0c728542b8b81d95b801a57b3797f9dd6e");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hmac_drbg_generate(hdrbg, 0, NULL, 0, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 32, "bfbdcf455d5c82acafc59f339ce57126ff70b67aef910fa25db7617818faeafe");
	status += CHECK_BLOCK(hdrbg->key, 32, "911bf7cbda4387a172a1a3daf6c9fa8e17c4bfef69cc7eff1341e7eef88d2811");
	status += CHECK_VALUE(hdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hmac_drbg_generate(hdrbg, 0, NULL, 0, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107"
		"694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8");

	status += CHECK_BLOCK(hdrbg->seed, 32, "6b94e773e3469353a1ca8face76b238c5919d62a150a7dfc589ffa11c30b5b94");
	status += CHECK_BLOCK(hdrbg->key, 32, "6dd2cd5b1edba4b620d195ce26ad6845b063211d11e591432de37a3ad793f66c");
	status += CHECK_VALUE(hdrbg->reseed_counter, 3);

	hmac_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Additional inputs

	hex_to_block(extra, 32, "972527fe90601de9d13a050c7e49d556d0de6b0e75e0619807ade2178eefe47d");

	hdrbg = hmac_drbg_new(hmac_drbg_sha256_entropy, HASH_SHA256, 65536, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 32, "0369222ee2c0a271fed4629e6954613f8b96a19174eaf6bace11822ef8a0db01");
	status += CHECK_BLOCK(hdrbg->key, 32, "fc24c5b12d7ead3a43c84ebf38c3ddede2b6691bf5aecd5bcd75afa4a205620f");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "0dc678372c9f24230d15acd1d36b13294c58b76f2847397fbc32dfada12b8e51");

	hmac_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 32, "0e4aa4aeca304d1918e7c92dba0eaf92f8c348ecc031ab9efa75232448133066");
	status += CHECK_BLOCK(hdrbg->key, 32, "26b7fa53a19ef63898ed51cfe9bbb9cf48ef26047a24d491cfabaa85ee83ad96");
	status += CHECK_VALUE(hdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "59874caea33944638e1e11fa3626fa2bc26d4502120c17e0e198d04f9ef0ff95");
	hmac_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"79db15ff50059ce58dcd44553f5cb6a19554cf35d2b64c869336a797cef93b24c64b716aaa11cd82dca0143279ed7cb2698d7cd726241ca17b5ce6831b08ae84dd"
		"57f95b11c07f7fef1d381eb0b7fd535b902ccede73538155f30100fd13ff007806b367f5032561338a92541f441725eab17996dd58e9870025d98b4752b547");
	status += CHECK_BLOCK(hdrbg->seed, 32, "93a426a8cb14dd95d443cd301eb94e7c4c365740797b2f2853adb7dbd6de9dd3");
	status += CHECK_BLOCK(hdrbg->key, 32, "b559747acecd08edf539dd2e4f5465ecb0dee108181d15781015e482bb7ff958");
	status += CHECK_VALUE(hdrbg->reseed_counter, 3);

	hmac_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Reseed

	hex_to_block(extra, 32, "27e38c624a8f934e931e195a0cbcf38e4e8d50108dc318743fb4b61cf78a7d14");

	hdrbg = hmac_drbg_new(hmac_drbg_sha256_entropy, HASH_SHA256, 65536, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 32, "65ee4461fd700036721800d2a71f5110cc8099fe447d4b68f317b821983a2063");
	status += CHECK_BLOCK(hdrbg->key, 32, "ac0e155af29e01caf36f5f36944adf9cef01b18a4a7aa5af8d63cd56a1d03d43");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	hex_to_block(extra, 32, "0e4dddbe0034180b59303d527a938a447bad9e4a91787d1072e6f41350ff11e5");
	hmac_drbg_reseed(hdrbg, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 32, "1de6328fc0c04353018c24e671c0828229d2bdb2faf331a9cb6363a68baf0ad9");
	status += CHECK_BLOCK(hdrbg->key, 32, "e21c915e4af5e628b7a45d2953dd61b552f256a215dd604a56067829bd4dfabe");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "cb25fccf929812b9fc66aea93e0cafb064e25b8c2989ae5078648ef529ecb487");
	hmac_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 32, "a3d029a688de1596b7a214af9f547d26e0d03bf3f62a5755e5288923b851c02e");
	status += CHECK_BLOCK(hdrbg->key, 32, "41b4ab280425b8e79e25011bcfeef18fbfa57b272100351a742afcabb5be78cf");
	status += CHECK_VALUE(hdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "c1685a422e4a0673cea9948937a8fdaa77777066f501aa17493682a83d931e6a");
	hmac_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"7569ff1ad01a56ab283c1f2357bd519e15c0be84b80cfe8ec6e26cf903aa8a17f52311a2458e48468122ce1f4abff12920f7dffa86c46f06d744d198004bdd0b29"
		"b1b0f17712863df82406e2c2a2fb73ea99dc3969c7e52aeaea031e0112fbf8d785426ae7c106d876a900ba54c4e9a1f3656990571c6d1fb56131cd1cdb1e68");
	status += CHECK_BLOCK(hdrbg->seed, 32, "53243974490ced473f3bc498415b40d75b08cd275bc596e5572aa14b9b51e054");
	status += CHECK_BLOCK(hdrbg->key, 32, "8d5ed0295e15688a8f9d7556fd452d63c6b0dff43e653b607cc79958cb305921");
	status += CHECK_VALUE(hdrbg->reseed_counter, 3);

	hmac_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Prediction resistance

	hex_to_block(extra, 32, "f293dc63e6e0dcb94bb19929a7935ec71bf16c55258eb66c63ff6d3225a8c270");

	hdrbg = hmac_drbg_new(hmac_drbg_sha256_entropy, HASH_SHA256, 65536, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 32, "af2a826550a0482185b35501838dd3b5d7673f92407559884c8a07389bc8a2d9");
	status += CHECK_BLOCK(hdrbg->key, 32, "709931023cb2c21917a43b9f8945932d0e5c0484d1f4164c8d44046e28d8aecd");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "4df6f301c1f2831f18ab0715706fc1e381c1c09a11ffc9af9938bd28a6fe700b");
	hmac_drbg_generate(hdrbg, 1, extra, 32, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 32, "f534194e68446e435954f03505b2bda9bdc7a00a836569944adff7abce96aacc");
	status += CHECK_BLOCK(hdrbg->key, 32, "8a2a3dd2f103aabee005bf3c53e017e42be31ced003728df50e3ce9e950fb7d4");
	status += CHECK_VALUE(hdrbg->reseed_counter, 2);

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

static uint32_t hash_drbg_sha256_entropy(void *state, void *buffer, uint32_t size)
{
	static uint32_t count = 0;

	UNUSED(state);

	switch (count)
	{
	case 0:
		hex_to_block(buffer, 32, "a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb");
		hex_to_block((byte_t *)buffer + 32, 16, "8581f9317517276e06e9607ddbcbcc2e");
		break;
	case 1:
		hex_to_block(buffer, 32, "b1a1a0a1f13a67d9d35441c96f8662e499f78a75b1c0a5c2e26dbde74cfa8489");
		hex_to_block((byte_t *)buffer + 32, 16, "e0c8a8ad309488f2043ba4afde664d10");
		break;
	case 2:
		hex_to_block(buffer, 32, "f05bab56c7ac6eeb31a0cf8a8a062a49179acf3c5b204d60dd7a3eb78f5d8e3b");
		hex_to_block((byte_t *)buffer + 32, 16, "a14508534168b688f05f1e419c88cc30");
		break;
	case 3:
		hex_to_block(buffer, 32, "72d402a2597b98a3b8f50b716c63c6dba73a07e65489063f02c532f5dac4d418");
		break;
	case 4:
		hex_to_block(buffer, 32, "7b03ece14ff63fc07722916b7cd062556fd688d5436d8bfa93d39e925598b180");
		hex_to_block((byte_t *)buffer + 32, 16, "5843f9c7a086bb92f9b80a008c0fd579");
		break;
	case 5:
		hex_to_block(buffer, 32, "b6dd12e258406e712318fe378b09cbe923d67848ac11992dea52f9c6508aa2ed");
		break;
	case 6:
		hex_to_block(buffer, 32, "c9c1b2fbcf6120d333393acabfac3aecda2e7a67f888f52df32d43ae0a2569aa");
		break;

	default:
		break;
	}

	++count;

	return size;
}

int32_t hash_drbg_test_suite()
{
	int32_t status = 0;
	hash_drbg *hdrbg = NULL;

	byte_t buffer[128] = {0};
	byte_t extra[32] = {0};

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Simple

	hdrbg = hash_drbg_new(hash_drbg_sha256_entropy, HASH_SHA256, 65536, NULL, 0);

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "6e2f8fe3cdcd8942bc19890b70e89dd37ef46dfbdc17c209941b1b236417b3704ae2e5bbbf289500068fd45b6b40b69c78944f611255cf");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "665fee50d6d7c604f96d68192ebfaf508ea88a193c7b9ccd04a47034ee7de5a9549a709b7201b38b307fdfe842ff1be8f7fcbce6c82a28");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hash_drbg_generate(hdrbg, 0, NULL, 0, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "d48f7e34a4a54f47b586f1249fa84d240d9cf81518935f09c40e32fe2b70cefff9715765773a401b85809bbceb0e8a12ff6e7d4e25281f");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "665fee50d6d7c604f96d68192ebfaf508ea88a193c7b9ccd04a47034ee7de5a9549a709b7201b38b307fdfe842ff1be8f7fcbce6c82a28");
	status += CHECK_VALUE(hdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hash_drbg_generate(hdrbg, 0, NULL, 0, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80daaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc3"
		"43e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df");

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "3aef6c857b7d154caef4593dce67fc749c45822e550efc1498b6cc482dce1492a6d442e2af5d76013490f5019bbb01f94476c212ea2eae");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "665fee50d6d7c604f96d68192ebfaf508ea88a193c7b9ccd04a47034ee7de5a9549a709b7201b38b307fdfe842ff1be8f7fcbce6c82a28");
	status += CHECK_VALUE(hdrbg->reseed_counter, 3);

	hash_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Additional inputs

	hex_to_block(extra, 32, "b54c1b191e08d33957b9e42712df4e64c8ee9ccc5c2e21a64748b36bb82315ed");

	hdrbg = hash_drbg_new(hash_drbg_sha256_entropy, HASH_SHA256, 65536, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "ac04382ddaaa86eb444112d2a9b1e57e2f5f1df3afbbbcb3c72f0b7b8043b748eb57476658e253972e4b3d9f5459d635673c0902282a7b");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "3bf764be99e1eb50d43019f77de267f6d6ffaa3f76859e350f21b5bd40de45bf872eff398e44c1f0f38b154575ced1f1a3db4f3eee87e4");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "7a57a675c9df3ec61a20194a34fbd9f75944b36ac33f755b5a4546830011f3f6");

	hash_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "e7fb9cec748c723c18712cca27944d75065ec83326415be69e322f13128b9ebe8c549a27fdf9d164ef63cf7fa89053bda560c64941c61d");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "3bf764be99e1eb50d43019f77de267f6d6ffaa3f76859e350f21b5bd40de45bf872eff398e44c1f0f38b154575ced1f1a3db4f3eee87e4");
	status += CHECK_VALUE(hdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "83e57b2d0f045d63f01cf2b43ca38b2b2f043fb2335f1bb1b571a813d561ede1");
	hash_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"884328b4186f195800c5896fabe2a0cee49151678508c71b7ac394981168535baf1d6cb5bd6e6a1bb32af4ebbd8ad74cdfb5a6339b20c3cdc671fdca1181567359"
		"79da11ed1e4a3fda76b4611407f6b8e80a3ed25802a4d431c01be668c52d37cd5b4f1cb61f57e3ff5ce0c374e2554e9ce311426a053299c3c846594e4bf536");
	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "23f301ab0e6e5d8ceca146c1a576b56bdd5e72729cc6fbff1785913c88295bf1e1286b4773504218534cc43bc66ef40904e098c55c1edb");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "3bf764be99e1eb50d43019f77de267f6d6ffaa3f76859e350f21b5bd40de45bf872eff398e44c1f0f38b154575ced1f1a3db4f3eee87e4");
	status += CHECK_VALUE(hdrbg->reseed_counter, 3);

	hash_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Reseed

	hex_to_block(extra, 32, "a03472f40459e287eacb2132c0b654027da3e66925b4212554c448188c0e8601");

	hdrbg = hash_drbg_new(hash_drbg_sha256_entropy, HASH_SHA256, 65536, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "67ea750051ac6d9debd6251fb910479e4fc987430fa65a6c93cff3b1eb4d31363120601f092dffeb40fe0c953022bb6c4b4da160ef76ce");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "9c1846671d24ab6fec65768297105cbc05c95860a77dafcd5aceb98ef826298d0ab3dfc9a6ebd1984382cd8390d42415bd363524ae0837");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	hex_to_block(extra, 32, "b30d28afa4116bbc136e6509b582a693bc91714046aa3c66b677b3eff9adfd49");
	hash_drbg_reseed(hdrbg, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "00fe5cec03fc719ca59a03897d61fce024ad5210be93ffc25cbe9b41a6a9f3e43ad947e920e1df86100a514ea5d9543f171f70657d8a62");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "a448b71f3dc2807227b67da919b82af35b5a8d4ebf012b720a59ae80c1d843c11932f9dcb8fcd9249920ded2e037c74feed2b31484009c");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "77fd1d68d6a4ddd5f327252d3f6bdfee8c35ced383beafc93277eff21b6ff41b");
	hash_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "a547140b41bef20ecd508132971a27d38007df5f7d952c31ad0f9f286020e66b7c1d65eea824fbe70c97f6c42eea8f5ce3eb7693722ace");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "a448b71f3dc2807227b67da919b82af35b5a8d4ebf012b720a59ae80c1d843c11932f9dcb8fcd9249920ded2e037c74feed2b31484009c");
	status += CHECK_VALUE(hdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "59a01ff86a58721e85d2f83f7399f1964e27f87fcd1bf5c1ebf337109b13bd24");
	hash_drbg_generate(hdrbg, 0, extra, 32, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"ff2796385c32bf843dfabbf03e705a39cba34cf14faec30563df5addbd2d3583f57e05f940305618f200881403c2d9813639e66755dcfc4e88ea71ddb2252e0991"
		"4940ebe23d6344a0f4db5ee839e670ec47243fa0fcf51361ce5398aabfb4191bfed500e1033a7654ffd724705e8cb2417d920a2f4f27b845137ffb8790a949");
	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "498fcb2a7f817280f506fedbb0d252c6db626cae3c96583a1de76082712c58b9dc29ddc66196c032ac7df836af29f7a71ae7159d555d76");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "a448b71f3dc2807227b67da919b82af35b5a8d4ebf012b720a59ae80c1d843c11932f9dcb8fcd9249920ded2e037c74feed2b31484009c");
	status += CHECK_VALUE(hdrbg->reseed_counter, 3);

	hash_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Prediction resistance

	hex_to_block(extra, 32, "ed4ca85d5cf89de5939759a8204bd91032c6db77418afb023538a87ee8324f4d");

	hdrbg = hash_drbg_new(hash_drbg_sha256_entropy, HASH_SHA256, 65536, extra, 32);

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "6fabba1fef3b6028ae81bb8867a6aba3830b279b6b821190cc31d967965af0fca4335a6682f0fdad61da755095de2f6d983f1953ddc354");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "e2bf43dc2cc78cdc11bc2643dfeffe4fcd6af6be8bc773118e97ec6d589bd9119a340a4f2b3c5e77db1c4755c9d5ceb9d528ff4a1cf28e");
	status += CHECK_VALUE(hdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "752d90f2b91a5286b6d3308c7676272f45e5fbd0f9bd9087b3766c0ffc3c81ef");
	hash_drbg_generate(hdrbg, 1, extra, 32, buffer, 128);

	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "ef1966668052073d358dc6a4c4d91bea9cfad3705901dc6f5595d642183b730bbcf3c5fc685a036ac5807caab47a9931332fd74967a559");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "2fd90e22a28dbdb5bb34703213de0e1c7e10eddbb57b13089cc2cea7ce89a60c679b47e62f10be0714794fb61c09dd9b508f0e4bd60e0b");
	status += CHECK_VALUE(hdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "9668cff92593ad0576f15925f5aa5dea577a7790ad1c20f8773907bfc70b9bb0");
	hash_drbg_generate(hdrbg, 1, extra, 32, buffer, 128);

	status += CHECK_BLOCK(
		buffer, 128,
		"91fb25cd4fd996a6994efe211972f3a1eb0011a2c0685cfdc4bdfd8d268088f56fdefac522e375713b8587ec407c62d255d207d15b3265ec64d34a5b7bb120703a"
		"b9bf6855407637ed8c2d24a4ed5b7026c271167f889bbc57929ca6d50ac6b6fc6873d925d1b5bfe4aee8e2eb649a43fd184ade51238d45ae9ce54dfcaaf7e1");
	status += CHECK_BLOCK(hdrbg->seed, 55,
						  "ad5091b8206d67ca34d5ecf00148b21fba3f41a9158a4056cfc244dae115f15147ab1815ffb6db9718b1b5dbab9ac47e742b1328b7f312");
	status += CHECK_BLOCK(hdrbg->constant, 55,
						  "a9cece42836ccefdab349f6921d43566fcbfbe64afac23fb4051b232c1f10c85f51623b07de25a1175eb7208486bc5485ab1c9ab6ae719");
	status += CHECK_VALUE(hdrbg->reseed_counter, 2);

	hash_drbg_delete(hdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

static uint32_t ctr_drbg_aes256_entropy(void *state, void *buffer, uint32_t size)
{
	static uint32_t count = 0;

	UNUSED(state);

	switch (count)
	{
	case 0:
		hex_to_block(buffer, 32, "36401940fa8b1fba91a1661f211d78a0b9389a74e5bccfece8d766af1a6d3b14");
		hex_to_block((byte_t *)buffer + 32, 16, "496f25b0f1301b4f501be30380a137eb");
		break;
	case 1:
		hex_to_block(buffer, 32, "6b536f8f4c5616a0c4e681825585724d522d37fc02a05564030872e0d6c3922f");
		hex_to_block((byte_t *)buffer + 32, 16, "0184417527ffdd3edddbb070957826c0");
		break;
	case 2:
		hex_to_block(buffer, 32, "e2f75cf553035b3cb4d21e567ca5c203623d4a4b5885326f63ea61a020a4984e");
		hex_to_block((byte_t *)buffer + 32, 16, "a666ee4b26dae5897fc5e85c643fc630");
		break;
	case 3:
		hex_to_block(buffer, 32, "f6672d022226b05db5d3c59c0da5b20a1be05ecabbd1744483ca4ce5571d93f4");
		break;
	case 4:
		hex_to_block(buffer, 32, "e02c6627df0c0422d2dfc7da9686daf8dce578966798d4e503530dd7db50130e");
		hex_to_block((byte_t *)buffer + 32, 16, "1b48e103c4091ac2f4581dba6a61858c");
		break;
	case 5:
		hex_to_block(buffer, 32, "323b97c0fe0060c94d0423f9e4424c9b92f769e170a3e1eabb72d78bec04bb27");
		break;
	case 6:
		hex_to_block(buffer, 32, "c96c87b9eeee3ca77689d8935d0163cf2679bd35af98b195cf0622bd85dc9578");
		break;

	default:
		break;
	}

	++count;

	return size;
}

int32_t ctr_drbg_test_suite()
{
	int32_t status = 0;
	ctr_drbg *cdrbg = NULL;

	byte_t buffer[128] = {0};
	byte_t extra[32] = {0};

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Simple

	cdrbg = ctr_drbg_new(ctr_drbg_aes256_entropy, CIPHER_AES256, 65536, NULL, 0);

	status += CHECK_BLOCK(cdrbg->key, 32, "3363d9000e6db47c16d3fc65f2872c08a35f99b2d174afa537a66ec153052d98");
	status += CHECK_BLOCK(cdrbg->block, 16, "9ee8d2e9c618ccbb8e66b5eb5333dce1");
	status += CHECK_VALUE(cdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	ctr_drbg_generate(cdrbg, 0, NULL, 0, buffer, 64);

	status += CHECK_BLOCK(cdrbg->key, 32, "b1dff09c816af6d4b2111fe63c4507cb196154f8c59957a94a2b641a7c16cc01");
	status += CHECK_BLOCK(cdrbg->block, 16, "69eec01b2dd4ff3aab5fac9467f54485");
	status += CHECK_VALUE(cdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	ctr_drbg_generate(cdrbg, 0, NULL, 0, buffer, 64);

	status += CHECK_BLOCK(
		buffer, 64,
		"5862eb38bd558dd978a696e6df164782ddd887e7e9a6c9f3f1fbafb78941b535a64912dfd224c6dc7454e5250b3d97165e16260c2faf1cc7735cb75fb4f07e1d");

	status += CHECK_BLOCK(cdrbg->key, 32, "33a1f160b0bde1dd55fc314c3d1620c0581ace8b32f062fb1ed54cdecdc17694");
	status += CHECK_BLOCK(cdrbg->block, 16, "f537c07f36573a26b3f55c8b9f7246d1");
	status += CHECK_VALUE(cdrbg->reseed_counter, 3);

	ctr_drbg_delete(cdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Additional inputs

	hex_to_block(extra, 32, "91e62a609b4db50c5e7ad7d09dc387dae9da6d2585bd3530389411cea7d2a40e");

	cdrbg = ctr_drbg_new(ctr_drbg_aes256_entropy, CIPHER_AES256, 65536, extra, 32);

	status += CHECK_BLOCK(cdrbg->key, 32, "a86cfae1c1c320f73e9d20a024a96105a1327eb32c9ace9f4158d39950861fbf");
	status += CHECK_BLOCK(cdrbg->block, 16, "660938f7e6fbc4238b8d5970acfcc436");
	status += CHECK_VALUE(cdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "42f398bf2229976f9d97b0a5fc47d5c64b70fa5631abf28f2c6f91f78b7278d9");

	ctr_drbg_generate(cdrbg, 0, extra, 32, buffer, 64);

	status += CHECK_BLOCK(cdrbg->key, 32, "f16822054dcb9e15fcc35aa14b43cee61f8d9756dc350af3199a97504e1875af");
	status += CHECK_BLOCK(cdrbg->block, 16, "622346663e083cb20218729af58fba31");
	status += CHECK_VALUE(cdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "c624291eb039ad1724c9b0ba20b98421a7f0032f6c8c00f64794018ce5a5ed96");
	ctr_drbg_generate(cdrbg, 0, extra, 32, buffer, 64);

	status += CHECK_BLOCK(
		buffer, 64,
		"507e0b4f12c408d87052b79eb4879c925a918b0fcd812bbedc720a3d8be656e40de900257f7a270dd6d8e7da50cdc20d744e94978d707b53f382aeb16488b122");
	status += CHECK_BLOCK(cdrbg->key, 32, "e90c8990876479e28fb7e4f9a15a6c65fe55aff1aa14bffbfb4ef037d3268c95");
	status += CHECK_BLOCK(cdrbg->block, 16, "ba2a09545efdc5f09a82014f632d226d");
	status += CHECK_VALUE(cdrbg->reseed_counter, 3);

	ctr_drbg_delete(cdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Reseed

	hex_to_block(extra, 32, "19275bbd7a0109d8179334c55337bc0a3f5ac48cb8c4959c888c0b65f7ac9a84");

	cdrbg = ctr_drbg_new(ctr_drbg_aes256_entropy, CIPHER_AES256, 65536, extra, 32);

	status += CHECK_BLOCK(cdrbg->key, 32, "7778c4dab6a0945bb276c82b1a17525a9bf9f128153ea11b12514b8ea925d7ea");
	status += CHECK_BLOCK(cdrbg->block, 16, "f20cb02cc8917f1ffbf1b41827182067");
	status += CHECK_VALUE(cdrbg->reseed_counter, 1);

	hex_to_block(extra, 32, "8c8f940af45aec864c8aa8be60b100f82bb9670c7e2a392a4ab6f4b20eefbbaa");
	ctr_drbg_reseed(cdrbg, extra, 32);

	status += CHECK_BLOCK(cdrbg->key, 32, "24343571d0cf186762a3eafa9107a1ed0c60885a8261b4a907fae7369510c42e");
	status += CHECK_BLOCK(cdrbg->block, 16, "16bf5a7afee786299d7c0b44375e70bb");
	status += CHECK_VALUE(cdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "26b5f0dadc891e0b1b78878e7ae75aee843376c0968c54c12759c18def21d363");
	ctr_drbg_generate(cdrbg, 0, extra, 32, buffer, 64);

	status += CHECK_BLOCK(cdrbg->key, 32, "f5d3d0da273749450d26fb333d81ac8b3f59f049abf3eb5a625394955f486130");
	status += CHECK_BLOCK(cdrbg->block, 16, "23f0a9d6741928dfd14d3823ec59207c");
	status += CHECK_VALUE(cdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "ff6791f4d4b29996b0399d95a14a28b8e2e20787531d916e7ed2ec040bbd7c84");
	ctr_drbg_generate(cdrbg, 0, extra, 32, buffer, 64);

	status += CHECK_BLOCK(
		buffer, 64,
		"eb8f289bb05be84084840c3d2c9deea0245487a98d7e1a4017b860e48635213d622a4a4eae91efdd5342ade94093f199c16deb1e58d0088b9b4a0f24a5d15775");
	status += CHECK_BLOCK(cdrbg->key, 32, "2ac85be48c4b86fea6a3c6826c3d495f03bf4a273a038578b78c3e642a5431e4");
	status += CHECK_BLOCK(cdrbg->block, 16, "57bc95505c2b95d293e628127ca2cb16");
	status += CHECK_VALUE(cdrbg->reseed_counter, 3);

	ctr_drbg_delete(cdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------
	// Prediction resistance

	hex_to_block(extra, 32, "0145aafa6ec83eb6525a8f2fa84ad630bb57bfe676a591900e18a4c0c4aa8402");

	cdrbg = ctr_drbg_new(ctr_drbg_aes256_entropy, CIPHER_AES256, 65536, extra, 32);

	status += CHECK_BLOCK(cdrbg->key, 32, "3d2ecef41efd871f7bea01244204b4d87cf8b72b5eeb6a12205dc5a8d0b3c76c");
	status += CHECK_BLOCK(cdrbg->block, 16, "4af7241a20af7a651a2c20beaf450311");
	status += CHECK_VALUE(cdrbg->reseed_counter, 1);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "fddddacb8c20182f16596a619105aae791696ee7aca308b5524383c178a27cc2");
	ctr_drbg_generate(cdrbg, 1, extra, 32, buffer, 64);

	status += CHECK_BLOCK(cdrbg->key, 32, "52166bb8609e11da91acf99948db35eb4dec23874f09f84c95d2babb78477aae");
	status += CHECK_BLOCK(cdrbg->block, 16, "a6cde557ae2df8c1df7a521d79083550");
	status += CHECK_VALUE(cdrbg->reseed_counter, 2);

	memset(buffer, 0, 128);
	hex_to_block(extra, 32, "d7e768a3281e4a43a0da59cd9af630548bcc2b95bff5c658b312b086f0fb54e4");
	ctr_drbg_generate(cdrbg, 1, extra, 32, buffer, 64);

	status += CHECK_BLOCK(
		buffer, 64,
		"493cdacfd25a678b8d8138bd4eff888b280d3e21e1fa73af3375d5914da958b1bed0233289ac49e59d56d5d40a7577fdc72304f8c8c8cb4ad4b216efa28180fd");
	status += CHECK_BLOCK(cdrbg->key, 32, "1a4d00964d882b31ca3d36db6fc92f6f0cfbd2f5ea86891ac7776c44d911734b");
	status += CHECK_BLOCK(cdrbg->block, 16, "6559a7fdf804e02e4062c0d7c9f7c7bf");

	ctr_drbg_delete(cdrbg);

	// -------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return hmac_drbg_test_suite() + hash_drbg_test_suite() + ctr_drbg_test_suite();
}
