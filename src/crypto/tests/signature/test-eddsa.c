/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <eddsa.h>
#include <sha.h>
#include <test.h>

// Refer RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA) for test vectors

int32_t ed25519_keygen_tests(void)
{
	int32_t status = 0;

	ed25519_key key = {0};
	byte_t private_key[ED25519_KEY_OCTETS] = {0};

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(private_key, 0, ED25519_KEY_OCTETS);

	hex_to_block(private_key, 32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
	ed25519_key_generate(&key, private_key);

	status += CHECK_BLOCK(key.public_key, 32, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(private_key, 0, ED25519_KEY_OCTETS);

	hex_to_block(private_key, 32, "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
	ed25519_key_generate(&key, private_key);

	status += CHECK_BLOCK(key.public_key, 32, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t ed448_keygen_tests(void)
{
	int32_t status = 0;

	ed448_key key = {0};
	byte_t private_key[ED448_KEY_OCTETS] = {0};

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(private_key, 0, ED448_KEY_OCTETS);

	hex_to_block(private_key, 57,
				 "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
	ed448_key_generate(&key, private_key);

	status +=
		CHECK_BLOCK(key.public_key, 57,
					"5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(private_key, 0, ED448_KEY_OCTETS);

	hex_to_block(private_key, 57,
				 "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328");
	ed448_key_generate(&key, private_key);

	status +=
		CHECK_BLOCK(key.public_key, 57,
					"dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t eddsa_25519_sign_tests(void)
{
	int32_t status = 0;

	ed25519_signature edsign = {0};
	ed25519_key key = {0};
	byte_t message[1024] = {0};

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(&edsign, 0, sizeof(ed25519_signature));
	memset(message, 0, 1024);

	hex_to_block(key.private_key, 32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
	hex_to_block(key.public_key, 32, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

	ed25519_sign(&key, NULL, 0, &edsign, sizeof(ed25519_signature));

	status += CHECK_BLOCK(
		edsign.sign, 64,
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(&edsign, 0, sizeof(ed25519_signature));
	memset(message, 0, 1024);

	hex_to_block(key.private_key, 32, "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
	hex_to_block(key.public_key, 32, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

	hex_to_block(message, 1, "72");

	ed25519_sign(&key, message, 1, &edsign, sizeof(ed25519_signature));

	status += CHECK_BLOCK(
		edsign.sign, 64,
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(&edsign, 0, sizeof(ed25519_signature));
	memset(message, 0, 1024);

	hex_to_block(key.private_key, 32, "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
	hex_to_block(key.public_key, 32, "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

	hex_to_block(message, 2, "af82");

	ed25519_sign(&key, message, 2, &edsign, sizeof(ed25519_signature));

	status += CHECK_BLOCK(
		edsign.sign, 64,
		"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(&edsign, 0, sizeof(ed25519_signature));
	memset(message, 0, 1024);

	hex_to_block(key.private_key, 32, "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
	hex_to_block(key.public_key, 32, "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");

	hex_to_block(
		message, 1023,
		"08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879"
		"de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a85"
		"8efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b"
		"33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c9"
		"4fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6"
		"248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c"
		"8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb"
		"75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae078"
		"4504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ad"
		"e8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f"
		"92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040c"
		"f9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8"
		"b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f"
		"17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3"
		"f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd30670"
		"5e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0");

	ed25519_sign(&key, message, 1023, &edsign, sizeof(ed25519_signature));

	status += CHECK_BLOCK(
		edsign.sign, 64,
		"0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(&edsign, 0, sizeof(ed25519_signature));
	memset(message, 0, 1024);

	hex_to_block(key.private_key, 32, "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
	hex_to_block(key.public_key, 32, "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");

	hex_to_block(
		message, 64,
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

	ed25519_sign(&key, message, 64, &edsign, sizeof(ed25519_signature));

	status += CHECK_BLOCK(
		edsign.sign, 64,
		"dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(&edsign, 0, sizeof(ed25519_signature));
	memset(message, 0, 1024);

	hex_to_block(key.private_key, 32, "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
	hex_to_block(key.public_key, 32, "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");

	hex_to_block(message, 3, "616263");

	ed25519ph_sign(&key, NULL, 0, message, 3, &edsign, sizeof(ed25519_signature));

	status += CHECK_BLOCK(
		edsign.sign, 64,
		"98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t eddsa_448_sign_tests(void)
{
	int32_t status = 0;

	ed448_signature edsign = {0};
	ed448_key key = {0};
	byte_t message[1024] = {0};
	byte_t context[1024] = {0};

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
	hex_to_block(key.public_key, 57,
				 "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");

	ed448_sign(&key, NULL, 0, NULL, 0, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d"
					"2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");
	hex_to_block(key.public_key, 57,
				 "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");

	hex_to_block(message, 1, "03");

	ed448_sign(&key, NULL, 0, message, 1, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0d"
					"bcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");
	hex_to_block(key.public_key, 57,
				 "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");

	hex_to_block(message, 1, "03");
	hex_to_block(context, 3, "666f6f");

	ed448_sign(&key, context, 3, message, 1, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85"
					"741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328");
	hex_to_block(key.public_key, 57,
				 "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400");

	hex_to_block(message, 11, "0c3e544074ec63b0265e0c");

	ed448_sign(&key, NULL, 0, message, 11, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8db"
					"deea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b");
	hex_to_block(key.public_key, 57,
				 "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580");

	hex_to_block(message, 12, "64a65f3cdedcdd66811e2915");

	ed448_sign(&key, NULL, 0, message, 12, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c"
					"2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e");
	hex_to_block(key.public_key, 57,
				 "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80");

	hex_to_block(message, 13, "64a65f3cdedcdd66811e2915e7");

	ed448_sign(&key, NULL, 0, message, 13, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5"
					"a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01");
	hex_to_block(key.public_key, 57,
				 "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00");

	hex_to_block(
		message, 64,
		"bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944");

	ed448_sign(&key, NULL, 0, message, 64, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63"
					"d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5");
	hex_to_block(key.public_key, 57,
				 "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00");

	hex_to_block(
		message, 256,
		"15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89e5"
		"cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072fc1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a6039c3"
		"c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce012d901"
		"015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11");

	ed448_sign(&key, NULL, 0, message, 256, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4"
					"f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8");
	hex_to_block(key.public_key, 57,
				 "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400");

	hex_to_block(
		message, 1023,
		"6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd86"
		"ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e97266"
		"0cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd323219b8033"
		"a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab797172b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813a30e5bb1"
		"2cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f52096cd1956d0"
		"42a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998d0d8fd25997c"
		"7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6155baee3b0773c"
		"0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db977025e7f5924388c"
		"7e340a732e554440e76570f8dd71b7d640b3450d1fd5f0410a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456f70703497a07876382"
		"9bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3120f19cfb2963f177aeb"
		"70f2d4844826262e51b80271272068ef5b3856fa8535aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf9696149e4ac824ad3460538fdc25"
		"421beec2cc6818162d06bbed0c40a387192349db67a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a6059d76b96a6fd857def5e0b354"
		"b27ab937a5815d16b5fae407ff18222c6d1ed263be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d02bf07e0ac8b5bc6162cf94697"
		"b3c27cd1fea49b27f23ba2901871962506520c392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e79a5f5db82571ba97bae3ad3e047"
		"9515bb0e2b0f3bfcd1fd33034efc6245eddd7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4b34973551257713b753632efba3481"
		"69abc90a68f42611a40126d7cb21b58695568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87");

	ed448_sign(&key, NULL, 0, message, 1023, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bddf7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6"
					"a0484fe76d76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed573603ce30d8bb761785dc30dbc320869e1a00");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49");
	hex_to_block(key.public_key, 57,
				 "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880");

	hex_to_block(message, 3, "616263");

	ed448ph_sign(&key, NULL, 0, message, 3, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d"
					"9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49");
	hex_to_block(key.public_key, 57,
				 "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880");

	hex_to_block(message, 3, "616263");
	hex_to_block(context, 3, "666f6f");

	ed448ph_sign(&key, context, 3, message, 3, &edsign, sizeof(ed448_signature));

	status +=
		CHECK_BLOCK(edsign.sign, 114,
					"c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa481065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d912"
					"24ba9911a3653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab71284f8d0704a608c54a6b62d97beb511d132100");

	// ----------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t eddsa_25519_verify_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	ed25519_signature edsign = {0};
	ed25519_key key = {0};
	byte_t message[1024] = {0};

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(&edsign, 0, sizeof(ed25519_signature));
	memset(message, 0, 1024);

	hex_to_block(key.private_key, 32, "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
	hex_to_block(key.public_key, 32, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
	hex_to_block(
		edsign.sign, 64,
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

	hex_to_block(message, 1, "72");

	result = ed25519_verify(&key, &edsign, message, 1);
	status += CHECK_VALUE(result, 1);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(&edsign, 0, sizeof(ed25519_signature));
	memset(message, 0, 1024);

	hex_to_block(key.private_key, 32, "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
	hex_to_block(key.public_key, 32, "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
	hex_to_block(
		edsign.sign, 64,
		"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

	hex_to_block(message, 2, "af82");

	result = ed25519_verify(&key, &edsign, message, 1);
	status += CHECK_VALUE(result, 1);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed25519_key));
	memset(&edsign, 0, sizeof(ed25519_signature));
	memset(message, 0, 1024);

	hex_to_block(key.private_key, 32, "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
	hex_to_block(key.public_key, 32, "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
	hex_to_block(
		edsign.sign, 64,
		"98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406");

	hex_to_block(message, 3, "616263");

	result = ed25519ph_verify(&key, &edsign, NULL, 0, message, 3);
	status += CHECK_VALUE(result, 1);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int32_t eddsa_448_verify_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	ed448_signature edsign = {0};
	ed448_key key = {0};
	byte_t message[1024] = {0};
	byte_t context[1024] = {0};

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");
	hex_to_block(key.public_key, 57,
				 "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");
	hex_to_block(edsign.sign, 114,
				 "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85"
				 "741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00");

	hex_to_block(message, 1, "03");
	hex_to_block(context, 3, "666f6f");

	result = ed448_verify(&key, &edsign, context, 3, message, 1);
	status += CHECK_VALUE(result, 1);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328");
	hex_to_block(key.public_key, 57,
				 "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400");
	hex_to_block(edsign.sign, 114,
				 "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8db"
				 "deea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00");

	hex_to_block(message, 11, "0c3e544074ec63b0265e0c");

	result = ed448_verify(&key, &edsign, NULL, 0, message, 11);
	status += CHECK_VALUE(result, 1);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	memset(&key, 0, sizeof(ed448_key));
	memset(&edsign, 0, sizeof(ed448_signature));
	memset(message, 0, 1024);
	memset(context, 0, 1024);

	hex_to_block(key.private_key, 57,
				 "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49");
	hex_to_block(key.public_key, 57,
				 "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880");
	hex_to_block(edsign.sign, 114,
				 "c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa481065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d912"
				 "24ba9911a3653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab71284f8d0704a608c54a6b62d97beb511d132100");

	hex_to_block(message, 3, "616263");
	hex_to_block(context, 3, "666f6f");

	result = ed448ph_verify(&key, &edsign, context, 3, message, 3);
	status += CHECK_VALUE(result, 1);

	// ----------------------------------------------------------------------------------------------------------------------------------------

	return status;
}

int main()
{
	return ed25519_keygen_tests() + ed448_keygen_tests() + eddsa_25519_sign_tests() + eddsa_448_sign_tests() + eddsa_25519_verify_tests() +
		   eddsa_448_verify_tests();
}
