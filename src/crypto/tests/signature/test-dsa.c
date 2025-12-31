/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <dsa.h>
#include <sha.h>
#include <test.h>

int32_t dsa_sign_tests(void)
{
	int32_t status = 0;

	dsa_group *group = NULL;
	dsa_key *key = NULL;
	bignum_t *p = NULL, *q = NULL, *g = NULL, *x = NULL, *y = NULL;

	dsa_signature *dsign = NULL;
	byte_t salt[512] = {0};
	byte_t message[512] = {0};
	byte_t hash[64] = {0};

	// ----------------------------------------------------------------------------------------------------------------------------------------

	p = bignum_set_hex(
		NULL,
		"cba13e533637c37c0e80d9fcd052c1e41a88ac325c4ebe13b7170088d54eef4881f3d35eae47c210385a8485d2423a64da3ffda63a26f92cf5a304f39260384a9b"
		"7759d8ac1adc81d3f8bfc5e6cb10efb4e0f75867f4e848d1a338586dd0648feeb163647ffe7176174370540ee8a8f588da8cc143d939f70b114a7f981b8483",
		256);

	q = bignum_set_hex(NULL, "95031b8aa71f29d525b773ef8b7c6701ad8a5d99", 40);

	g = bignum_set_hex(
		NULL,
		"45bcaa443d4cd1602d27aaf84126edc73bd773de6ece15e97e7fef46f13072b7adcaf7b0053cf4706944df8c4568f26c997ee7753000fbe477a37766a4e970ff40"
		"008eb900b9de4b5f9ae06e06db6106e78711f3a67feca74dd5bddcdf675ae4014ee9489a42917fbee3bb9f2a24df67512c1c35c97bfbf2308eaacd28368c5c",
		256);

	x = bignum_set_hex(NULL, "2eac4f4196fedb3e651b3b00040184cfd6da2ab4", 40);

	y = bignum_set_hex(
		NULL,
		"4cd6178637d0f0de1488515c3b12e203a3c0ca652f2fe30d088dc7278a87affa634a727a721932d671994a958a0f89223c286c3a9b10a96560542e2626b72e0cd2"
		"8e5133fb57dc238b7fab2de2a49863ecf998751861ae668bf7cad136e6933f57dfdba544e3147ce0e7370fa6e8ff1de690c51b4aeedf0485183889205591e8",
		256);

	group = dh_group_custom_new(p, q, g);
	key = dsa_key_new(group, x, y);

	hex_to_block(
		message, 128,
		"812172f09cbae62517804885754125fc6066e9a902f9db2041eeddd7e8da67e4a2e65d0029c45ecacea6002f9540eb1004c883a8f900fd84a98b5c449ac49c56f3"
		"a91d8bed3f08f427935fbe437ce46f75cd666a0707265c61a096698dc2f36b28c65ec7b6e475c8b67ddfb444b2ee6a984e9d6d15233e25e44bd8d7924d129d");

	hex_to_block(salt, 20, "85976c5610a74959531040a5512b347eac587e48");

	sha256_hash(message, 128, hash);

	dsign = dsa_signature_new(key);
	dsign = dsa_sign(key, dsign, salt, 20, hash, SHA256_HASH_SIZE);

	status += CHECK_BLOCK(dsign->r.sign, 20, "76683a085d6742eadf95a61af75f881276cfd26a");
	status += CHECK_BLOCK(dsign->s.sign, 20, "3b9da7f9926eaaad0bebd4845c67fcdb64d12453");

	status += CHECK_VALUE(dsign->r.size, 20);
	status += CHECK_VALUE(dsign->s.size, 20);

	dsa_signature_delete(dsign);
	dsa_key_delete(key);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	p = bignum_set_hex(
		NULL,
		"a4c7eaab42c4c73b757770916489f17cd50725cd0a4bc4e1cf67f763b8c1de2d6dab9856baafb008f365b18a42e14dc51f350b88eca0209c5aa4fd71a7a96c765f"
		"5901c21e720570d7837bec7c76d2e49344731ca39405d0a879b9e0dcd1a8125fd130ec1e783e654b94e3002e6b629e904ab3877867720cbd54b4270a9e15cd028c"
		"7cc796f06c272a660951928fdbeb2dca061b41e932257305742ff16e2f429191d5e5f1a6ddf6e78c5d7722cff80a9c0bd5c8d7aeba8c04438992b075e307c1534c"
		"49ad380f477f5f7987dc172c161dca38dcaf3fb3846c72c9119a5299adc748951b3dce0d00d4a9013800b2008203b72465bc6a84ae059a30c4522dea57",
		512);

	q = bignum_set_hex(NULL, "ce89fe332b8e4eb3d1e8ddcea5d163a5bc13b63f16993755427aef43", 56);

	g = bignum_set_hex(
		NULL,
		"8c465edf5a180730291e080dfc5385397a5006450dba2efe0129264fbd897bb5579ca0eab19aa278220424724b4f2a6f6ee6328432abf661380646097233505339"
		"c5519d357d7112b6eec938b85d5aa75cc2e38092f0a530acb54e50fe82c4d562fb0f3036b80b30334023ebbe6637a0010b00c7db86371168563671e1e0f028aedb"
		"d45d2d572621a609982a073e51aae27707afbeef29e2ecee84d7a6d5da382be3a35f42b6c66849202ab19d025b869d08776476d1ab981475ad2ad2f3e6fd07e306"
		"96d90a626816df60d6ca7afd7b482f942f83b45cc82933731f87faee320900f2aa3e70b1867e1430e40be67c07f9290299ef067b8b24a7515b3f992c07",
		512);

	x = bignum_set_hex(NULL, "551595eccbb003b0bf8ddda184a59da51e459a0d28205e5592ca4cb1", 56);

	y = bignum_set_hex(
		NULL,
		"748a40237211a2d9852596e7a891f43d4eb0ee48826c9cfb336bbb68dbe5a5e16b2e1271d4d13de03644bb85ef6be523a4d4d88415bcd596ba8e0a3c4f6439e981"
		"ed013d7d9c70336febf7d420cfed02c267457bb3f3e7c82145d2af54830b942ec74a5d503e4226cd25dd75decd3f50f0a858155d7be799410836ddc559ce99e1ae"
		"513808fdaeac34843dd7258f16f67f19205f6f139251a4186da8496d5e90d3fecf8ed10be6c25ff5eb33d960c9a8f4c581c8c724ca43b761e9fdb5af66bffb9d2e"
		"bb11a6b504a1fbe4f834ecb6ac254cab513e943b9a953a7084b3305c661bfad434f6a835503c9ade7f4a57f5c965ec301ecde938ee31b4deb038af97b3",
		512);

	group = dh_group_custom_new(p, q, g);
	key = dsa_key_new(group, x, y);

	hex_to_block(
		message, 128,
		"cec8d2843dee7cb5f9119b75562585e05c5ce2f4e6457e9bcc3c1c781ccd2c0442b6282aea610f7161dcede176e774861f7d2691be6c894ac3ebf80c0fab21e52a"
		"3e63ae0b35025762ccd6c9e1fecc7f9fe00aa55c0c3ae33ae88f66187f9598eba9f863171f3f56484625bf39d883427349b8671d9bb7d396180694e5b546ae");

	hex_to_block(salt, 28, "6f326546aa174b3d319ef7331ec8dfd363dd78ae583a920165ff7e54");

	sha256_hash(message, 128, hash);

	dsign = dsa_signature_new(key);
	dsign = dsa_sign(key, dsign, salt, 28, hash, SHA256_HASH_SIZE);

	status += CHECK_BLOCK(dsign->r.sign, 28, "9c5fa46879ddaf5c14f07dfb5320715f67a6fec179e3ad53342fb6d1");
	status += CHECK_BLOCK(dsign->s.sign, 28, "c3e17e7b3c4d0ac8d49f4dd0f04c16a094f42da0afcc6c90f5f1bbc8");

	status += CHECK_VALUE(dsign->r.size, 28);
	status += CHECK_VALUE(dsign->s.size, 28);

	dsa_signature_delete(dsign);
	dsa_key_delete(key);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	p = bignum_set_hex(
		NULL,
		"a8adb6c0b4cf9588012e5deff1a871d383e0e2a85b5e8e03d814fe13a059705e663230a377bf7323a8fa117100200bfd5adf857393b0bbd67906c081e585410e38"
		"480ead51684dac3a38f7b64c9eb109f19739a4517cd7d5d6291e8af20a3fbf17336c7bf80ee718ee087e322ee41047dabefbcc34d10b66b644ddb3160a28c06395"
		"63d71993a26543eadb7718f317bf5d9577a6156561b082a10029cd44012b18de6844509fe058ba87980792285f2750969fe89c2cd6498db3545638d5379d125dcc"
		"f64e06c1af33a6190841d223da1513333a7c9d78462abaab31b9f96d5f34445ceb6309f2f6d2c8dde06441e87980d303ef9a1ff007e8be2f0be06cc15f",
		512);

	q = bignum_set_hex(NULL, "e71f8567447f42e75f5ef85ca20fe557ab0343d37ed09edc3f6e68604d6b9dfb", 64);

	g = bignum_set_hex(
		NULL,
		"5ba24de9607b8998e66ce6c4f812a314c6935842f7ab54cd82b19fa104abfb5d84579a623b2574b37d22ccae9b3e415e48f5c0f9bcbdff8071d63b9bb956e547af"
		"3a8df99e5d3061979652ff96b765cb3ee493643544c75dbe5bb39834531952a0fb4b0378b3fcbb4c8b5800a5330392a2a04e700bb6ed7e0b85795ea38b1b962741"
		"b3f33b9dde2f4ec1354f09e2eb78e95f037a5804b6171659f88715ce1a9b0cc90c27f35ef2f10ff0c7c7a2bb0154d9b8ebe76a3d764aa879af372f4240de834793"
		"7e5a90cec9f41ff2f26b8da9a94a225d1a913717d73f10397d2183f1ba3b7b45a68f1ff1893caf69a827802f7b6a48d51da6fbefb64fd9a6c5b75c4561",
		512);

	x = bignum_set_hex(NULL, "446969025446247f84fdea74d02d7dd13672b2deb7c085be11111441955a377b", 64);

	y = bignum_set_hex(
		NULL,
		"5a55dceddd1134ee5f11ed85deb4d634a3643f5f36dc3a70689256469a0b651ad22880f14ab85719434f9c0e407e60ea420e2a0cd29422c4899c416359dbb1e592"
		"456f2b3cce233259c117542fd05f31ea25b015d9121c890b90e0bad033be1368d229985aac7226d1c8c2eab325ef3b2cd59d3b9f7de7dbc94af1a9339eb430ca36"
		"c26c46ecfa6c5481711496f624e188ad7540ef5df26f8efacb820bd17a1f618acb50c9bc197d4cb7ccac45d824a3bf795c234b556b06aeb929173453252084003f"
		"69fe98045fe74002ba658f93475622f76791d9b2623d1b5fff2cc16844746efd2d30a6a8134bfc4c8cc80a46107901fb973c28fc553130f3286c1489da",
		512);

	group = dh_group_custom_new(p, q, g);
	key = dsa_key_new(group, x, y);

	hex_to_block(
		message, 128,
		"4e3a28bcf90d1d2e75f075d9fbe55b36c5529b17bc3a9ccaba6935c9e20548255b3dfae0f91db030c12f2c344b3a29c4151c5b209f5e319fdf1c23b190f64f1fe5"
		"b330cb7c8fa952f9d90f13aff1cb11d63181da9efc6f7e15bfed4862d1a62c7dcf3ba8bf1ff304b102b1ec3f1497dddf09712cf323f5610a9d10c3d9132659");

	hex_to_block(salt, 32, "117a529e3fdfc79843a5a4c07539036b865214e014b4928c2a31f47bf62a4fdb");

	sha256_hash(message, 128, hash);

	dsign = dsa_signature_new(key);
	dsign = dsa_sign(key, dsign, salt, 32, hash, SHA256_HASH_SIZE);

	status += CHECK_BLOCK(dsign->r.sign, 32, "633055e055f237c38999d81c397848c38cce80a55b649d9e7905c298e2a51447");
	status += CHECK_BLOCK(dsign->s.sign, 32, "2bbf68317660ec1e4b154915027b0bc00ee19cfc0bf75d01930504f2ce10a8b0");

	status += CHECK_VALUE(dsign->r.size, 32);
	status += CHECK_VALUE(dsign->s.size, 32);

	dsa_signature_delete(dsign);
	dsa_key_delete(key);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	p = bignum_set_hex(
		NULL,
		"c7b86d7044218e367453d210e76433e4e27a983db1c560bb9755a8fb7d819912c56cfe002ab1ff3f72165b943c0b28ed46039a07de507d7a29f738603decd12703"
		"80a41f971f2592661a64ba2f351d9a69e51a888a05156b7fe1563c4b77ee93a44949138438a2ab8bdcfc49b4e78d1cde766e54984760057d76cd740c94a4dd25a4"
		"6aa77b18e9d707d6738497d4eac364f4792d9766a16a0e234807e96b8c64d404bbdb876e39b5799ef53fe6cb9bab62ef19fdcc2bdd905beda13b9ef7ac35f1f557"
		"cb0dc458c019e2bc19a9f5dfc1e4eca9e6d466564124304a31f038605a3e342da01be1c2b545610edd2c1397a3c8396588c6329efeb4e165af5b368a39a88e4888"
		"e39f40bb3de4eb1416672f999fead37aef1ca9643ff32cdbc0fcebe628d7e46d281a989d43dd21432151af68be3f6d56acfbdb6c97d87fcb5e6291bf8b4ee1275a"
		"e0eb4383cc753903c8d29f4adb6a547e405decdff288c5f6c7aa30dcb12f84d392493a70933317c0f5e6552601fae18f17e6e5bb6bf396d32d8ab9",
		768);

	q = bignum_set_hex(NULL, "876fa09e1dc62b236ce1c3155ba48b0ccfda29f3ac5a97f7ffa1bd87b68d2a4b", 64);

	g = bignum_set_hex(
		NULL,
		"110afebb12c7f862b6de03d47fdbc3326e0d4d31b12a8ca95b2dee2123bcc667d4f72c1e7209767d2721f95fbd9a4d03236d54174fbfaff2c4ff7deae4738b20d9"
		"f37bf0a1134c288b420af0b5792e47a92513c0413f346a4edbab2c45bdca13f5341c2b55b8ba54932b9217b5a859e553f14bb8c120fbb9d99909dff5ea68e14b37"
		"9964fd3f3861e5ba5cc970c4a180eef54428703961021e7bd68cb637927b8cbee6805fa27285bfee4d1ef70e02c1a18a7cd78bef1dd9cdad45dde9cd690755050f"
		"c4662937ee1d6f4db12807ccc95bc435f11b71e7086048b1dab5913c6055012de82e43a4e50cf93feff5dcab814abc224c5e0025bd868c3fc592041bba04747c10"
		"af513fc36e4d91c63ee5253422cf4063398d77c52fcb011427cbfcfa67b1b2c2d1aa4a3da72645cb1c767036054e2f31f88665a54461c885fb3219d5ad8748a011"
		"58f6c7c0df5a8c908ba8c3e536822428886c7b500bbc15b49df746b9de5a78fe3b4f6991d0110c3cbff458039dc36261cf46af4bc2515368f4abb7",
		768);

	x = bignum_set_hex(NULL, "3470832055dade94e14cd8777171d18e5d06f66aeff4c61471e4eba74ee56164", 64);

	y = bignum_set_hex(
		NULL,
		"456a105c713566234838bc070b8a751a0b57767cb75e99114a1a46641e11da1fa9f22914d808ad7148612c1ea55d25301781e9ae0c9ae36a69d87ba039ec7cd864"
		"c3ad094873e6e56709fd10d966853d611b1cff15d37fdee424506c184d62c7033358be78c2250943b6f6d043d63b317de56e5ad8d1fd97dd355abe96452f8e4354"
		"85fb3b907b51900aa3f24418df50b4fcdafbf6137548c39373b8bc4ba3dabb4746ebd17b87fcd6a2f197c107b18ec5b465e6e4cb430d9c0ce78da5988441054a37"
		"0792b730da9aba41a3169af26176f74e6f7c0c9c9b55b62bbe7ce38d4695d48157e660c2acb63f482f55418150e5fee43ace84c540c3ba7662ae80835c1a2d5189"
		"0ea96ba206427c41ef8c38aa07d2a365e7e58380d8f4782e22ac2101af732ee22758337b253637838e16f50f56d313d07981880d685557f7d79a6db823c61f1bb3"
		"dbc5d50421a4843a6f29690e78aa0f0cff304231818b81fc4a243fc00f09a54c466d6a8c73d32a55e1abd5ec8b4e1afa32a79b01df85a81f3f5cfe",
		768);

	group = dh_group_custom_new(p, q, g);
	key = dsa_key_new(group, x, y);

	hex_to_block(
		message, 128,
		"cb06e02234263c22b80e832d6dc5a1bee5ea8af3bc2da752441c04027f176158bfe68372bd67f84d489c0d49b07d4025962976be60437be1a2d01d3be0992afa5a"
		"be0980e26a9da4ae72f827b423665195cc4eed6fe85c335b32d9c03c945a86e7fa99373f0a30c6eca938b3afb6dff67adb8bece6f8cfec4b6a12ea281e2323");

	hex_to_block(salt, 32, "3d7c068a3978b2d8fe9034bcad65ad7c300c4440e4085de280e577eea72c1207");

	sha256_hash(message, 128, hash);

	dsign = dsa_signature_new(key);
	dsign = dsa_sign(key, dsign, salt, 32, hash, SHA256_HASH_SIZE);

	status += CHECK_BLOCK(dsign->r.sign, 32, "53bae6c6f336e2eb311c1e92d95fc449a929444ef81ec4279660b200d59433de");
	status += CHECK_BLOCK(dsign->s.sign, 32, "49f3a74e953e77a7941af3aefeef4ed499be209976a0edb3fa5e7cb961b0c112");

	status += CHECK_VALUE(dsign->r.size, 32);
	status += CHECK_VALUE(dsign->s.size, 32);

	dsa_signature_delete(dsign);
	dsa_key_delete(key);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return dsa_sign_tests();
}
