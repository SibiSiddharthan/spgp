/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <ecdsa.h>
#include <sha.h>
#include <test.h>

int32_t ecdsa_prime_sign_tests(void)
{
	int32_t status = 0;

	ec_group *group = NULL;
	bignum_t *d = NULL, *qx = NULL, *qy = NULL;

	ec_key key;
	ec_point q;

	ecdsa_signature *ecsign = NULL;
	byte_t salt[512] = {0};
	byte_t message[512] = {0};
	byte_t hash[64] = {0};

	group = ec_group_new(EC_NIST_P256);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	key.eg = group;

	d = bignum_set_hex(NULL, "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464", 64);
	qx = bignum_set_hex(NULL, "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83", 64);
	qy = bignum_set_hex(NULL, "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9", 64);

	q.x = qx;
	q.y = qy;

	key.d = d;
	key.q = &q;

	memset(message, 0, 512);
	hex_to_block(
		message, 128,
		"5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb547"
		"3e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8");

	memset(salt, 0, 512);
	hex_to_block(salt, 32, "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de");

	sha256_hash(message, 128, hash);

	ecsign = ecdsa_signature_new(&key);
	ecsign = ecdsa_sign(&key, ecsign, salt, 32, hash, SHA256_HASH_SIZE);

	status += CHECK_BLOCK(ecsign->r.sign, 32, "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac");
	status += CHECK_BLOCK(ecsign->s.sign, 32, "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903");

	status += CHECK_VALUE(ecsign->r.size, 32);
	status += CHECK_VALUE(ecsign->s.size, 32);

	bignum_delete(d);
	bignum_delete(qx);
	bignum_delete(qy);

	ecdsa_signature_delete(ecsign);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	key.eg = group;

	d = bignum_set_hex(NULL, "53a0e8a8fe93db01e7ae94e1a9882a102ebd079b3a535827d583626c272d280d", 64);
	qx = bignum_set_hex(NULL, "1bcec4570e1ec2436596b8ded58f60c3b1ebc6a403bc5543040ba82963057244", 64);
	qy = bignum_set_hex(NULL, "8af62a4c683f096b28558320737bf83b9959a46ad2521004ef74cf85e67494e1", 64);

	q.x = qx;
	q.y = qy;

	key.d = d;
	key.q = &q;

	memset(message, 0, 512);
	hex_to_block(
		message, 128,
		"dc66e39f9bbfd9865318531ffe9207f934fa615a5b285708a5e9c46b7775150e818d7f24d2a123df3672fff2094e3fd3df6fbe259e3989dd5edfcccbe7d45e26a7"
		"75a5c4329a084f057c42c13f3248e3fd6f0c76678f890f513c32292dd306eaa84a59abe34b16cb5e38d0e885525d10336ca443e1682aa04a7af832b0eee4e7");

	memset(salt, 0, 512);
	hex_to_block(salt, 32, "5d833e8d24cc7a402d7ee7ec852a3587cddeb48358cea71b0bedb8fabe84e0c4");

	sha256_hash(message, 128, hash);

	ecsign = ecdsa_signature_new(&key);
	ecsign = ecdsa_sign(&key, ecsign, salt, 32, hash, SHA256_HASH_SIZE);

	status += CHECK_BLOCK(ecsign->r.sign, 32, "18caaf7b663507a8bcd992b836dec9dc5703c080af5e51dfa3a9a7c387182604");
	status += CHECK_BLOCK(ecsign->s.sign, 32, "77c68928ac3b88d985fb43fb615fb7ff45c18ba5c81af796c613dfa98352d29c");

	status += CHECK_VALUE(ecsign->r.size, 32);
	status += CHECK_VALUE(ecsign->s.size, 32);

	bignum_delete(d);
	bignum_delete(qx);
	bignum_delete(qy);

	ecdsa_signature_delete(ecsign);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	ec_group_delete(group);

	group = ec_group_new(EC_NIST_P384);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	key.eg = group;

	d = bignum_set_hex(NULL, "217afba406d8ab32ee07b0f27eef789fc201d121ffab76c8fbe3c2d352c594909abe591c6f86233992362c9d631baf7c", 96);
	qx = bignum_set_hex(NULL, "fb937e4a303617b71b6c1a25f2ac786087328a3e26bdef55e52d46ab5e69e5411bf9fc55f5df9994d2bf82e8f39a153e", 96);
	qy = bignum_set_hex(NULL, "a97d9075e92fa5bfe67e6ec18e21cc4d11fde59a68aef72c0e46a28f31a9d60385f41f39da468f4e6c3d3fbac9046765", 96);

	q.x = qx;
	q.y = qy;

	key.d = d;
	key.q = &q;

	memset(message, 0, 512);
	hex_to_block(
		message, 128,
		"67d9eb88f289454d61def4764d1573db49b875cfb11e139d7eacc4b7a79d3db3bf7208191b2b2078cbbcc974ec0da1ed5e0c10ec37f6181bf81c0f32972a125df6"
		"4e3b3e1d838ec7da8dfe0b7fcc911e43159a79c73df5fa252b98790be511d8a732fcbf011aacc7d45d8027d50a347703d613ceda09f650c6104c9459537c8f");

	memset(salt, 0, 512);
	hex_to_block(salt, 48, "90338a7f6ffce541366ca2987c3b3ca527992d1efcf1dd2723fbd241a24cff19990f2af5fd6419ed2104b4a59b5ae631");

	sha512_hash(message, 128, hash);

	ecsign = ecdsa_signature_new(&key);
	ecsign = ecdsa_sign(&key, ecsign, salt, 48, hash, SHA512_HASH_SIZE);

	status +=
		CHECK_BLOCK(ecsign->r.sign, 48, "c269d9c4619aafdf5f4b3100211dddb14693abe25551e04f9499c91152a296d7449c08b36f87d1e16e8e15fee4a7f5c8");
	status +=
		CHECK_BLOCK(ecsign->s.sign, 48, "77ffed5c61665152d52161dc13ac3fbae5786928a3d736f42d34a9e4d6d4a70a02d5af90fa37a23a318902ae2656c071");

	status += CHECK_VALUE(ecsign->r.size, 48);
	status += CHECK_VALUE(ecsign->s.size, 48);

	bignum_delete(d);
	bignum_delete(qx);
	bignum_delete(qy);

	ecdsa_signature_delete(ecsign);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	key.eg = group;

	d = bignum_set_hex(NULL, "9da37e104938019fbdcf247e3df879a282c45f8fb57e6655e36b47723af42bec3b820f660436deb3de123a21de0ca37b", 96);
	qx = bignum_set_hex(NULL, "722d0ea6891d509b18b85ca56f74deb5c3030d2a30433824123d430d03c99279572c3b28ecf01e747b9db8acc55d0ba3", 96);
	qy = bignum_set_hex(NULL, "7e2605ea7092214f366f3639037bffd89fe103c646e990839d3a1ced8d78edb5b9bc60d834fd8e2a3c17e920bdae023a", 96);

	q.x = qx;
	q.y = qy;

	key.d = d;
	key.q = &q;

	memset(message, 0, 512);
	hex_to_block(
		message, 128,
		"817d6a110a8fd0ca7b4d565558f68b59a156744d4c5aac5c6610c95451793de2a756f774558c61d21818d3ebeeeb71d132da1c23a02f4b305eccc5cd46bd21dfc1"
		"73a8a91098354f10ffbb21bf63d9f4c3feb231c736504549a78fd76d39f3ad35c36178f5c233742d2917d5611d2073124845f1e3615b2ef25199a7a547e882");

	memset(salt, 0, 512);
	hex_to_block(salt, 48, "c8c18e53a9aa5915288c33132bd09323638f7995cd89162073984ed84e72e07a37e18c4c023933eace92c35d10e6b1b6");

	sha512_hash(message, 128, hash);

	ecsign = ecdsa_signature_new(&key);
	ecsign = ecdsa_sign(&key, ecsign, salt, 48, hash, SHA512_HASH_SIZE);

	status +=
		CHECK_BLOCK(ecsign->r.sign, 48, "6512a8a2be731e301dcf4803764297862bbfa0ac8daed64d8e98b34618ecb20520fc5d3cf890b7783edf86e7ea407541");
	status +=
		CHECK_BLOCK(ecsign->s.sign, 48, "4ff10301f7b4168fae066361376007c1d7aa89a75c87719d0b54711ffef5ef3726f3eef84f7ebc025c110bde511b17f6");

	status += CHECK_VALUE(ecsign->r.size, 48);
	status += CHECK_VALUE(ecsign->s.size, 48);

	bignum_delete(d);
	bignum_delete(qx);
	bignum_delete(qy);

	ecdsa_signature_delete(ecsign);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	ec_group_delete(group);

	return status;
}

int main()
{
	return ecdsa_prime_sign_tests();
}
