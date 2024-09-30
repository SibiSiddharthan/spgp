/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <string.h>
#include <bignum.h>

#include <test.h>

int32_t bignum_modadd_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *b = NULL, *m = NULL, *r = NULL;
	char hex[256] = {0};

	// ------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"c590e57ee64fced18aff6e2f0c6ac05625b1e94f394f42470cae14d12cadea4f5ab6b9d77225fe3b4903825966c78752ae51b6a0a2caca555fd0ffcbd9704b01",
		128);
	b = bignum_set_hex(
		NULL,
		"2d595b9a41c2b5e81734cd843e9bdc16353775472e3cec09c6afa53d0b35f71c4b425847d9561bfae749362a32cf961afbf8fca85ecce12f5c25a1c7078d",
		124);
	m = bignum_set_hex(
		NULL, "49ff858c7081392defc3ba12ea8869fd61188ff15d9339be72657b00530b851de53b1fcbe16034816e73251fe1ec97bcecd8bccc470373974287ca328af",
		123);

	r = bignum_modadd(NULL, NULL, a, b, m);

	memset(hex, 0, 256);
	result = bignum_get_hex(r, hex, 256);

	status += CHECK_HEX(
		hex, "0x46b805098cdbe7cd8ebb6a57a8ef8524ad051eee6340366afdc8f26e75ebceed79f9bc367a48bd348710c64755af791b6de0a511cbaaf325491035432a",
		124);
	status += CHECK_VALUE(result, 124);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "81fae0f8555d46ede9e74a93b8a7c6273c9bee0eef0f51b4575aad5cbdc0e10a3d03d53cf2a42e6a3625074c812cd0ae41d94d34ee",
					   106);
	b = bignum_set_hex(
		NULL,
		"f6446ca2883d7e27209eea1e24fe4e46d2431ee114d1e1cc669c4bc5ce896ea92f92a501f92ce92152b205bf3d41fa90cf241f67c3d555f5a63db52408a17b25",
		128);
	m = bignum_set_hex(NULL,
					   "723db98a78f42aa45496f31cf78695583526d25e167da48ec310e447ad3540be2636813a2c2f7b8c622795ac451992e91bb8e43e5737f0dd956"
					   "23282e729d815b08ed8",
					   134);

	r = bignum_modadd(NULL, NULL, a, b, m);

	memset(hex, 0, 256);
	result = bignum_get_hex(r, hex, 256);

	status += CHECK_HEX(hex,
						"0xf6446ca2883d7e27209eeaa01fdf469c2f8a0ccafc1c75850e6273026a777d983ee4595953da45df13930ffc411737837352899de8dca276"
						"d30e6365e1eeb013",
						130);
	status += CHECK_VALUE(result, 130);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	return status;
}

int32_t bignum_modsub_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *b = NULL, *m = NULL, *r = NULL;
	char hex[256] = {0};

	// ------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"f6446ca2883d7e27209eeaa01fdf469c2f8a0ccafc1c75850e6273026a777d983ee4595953da45df13930ffc411737837352899de8dca276d30e6365e1eeb013",
		128);
	b = bignum_set_hex(NULL, "15773d29ba363a15a0cb31ac4a60c0c228967e857d7d11c1ebb0a8db855c0d0797c0e409899a50e1b1c989a7dcea6f26238d27", 102);
	m = bignum_set_hex(
		NULL, "49ff858c7081392defc3ba12ea8869fd61188ff15d9339be72657b00530b851de53b1fcbe16034816e73251fe1ec97bcecd8bccc470373974287ca328af",
		123);

	r = bignum_modsub(NULL, NULL, a, b, m);

	memset(hex, 0, 256);
	result = bignum_get_hex(r, hex, 256);

	status += CHECK_HEX(
		hex, "0xe7d7f4f152a7c353baca7ddb099758130a78a91179ba5ba75e418ecb016dab9e6b827413ecdd7053b8bcd33ed938ba77473ccfc4717c75756c137fde1e",
		124);
	status += CHECK_VALUE(result, 124);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	return status;
}

int32_t bignum_modsqr_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *m = NULL, *r = NULL;
	char hex[512] = {0};
	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL,
					   "1cc779145b2b7bf9ef4c9692845e162329940f96eb43e04db8728bfe736698082aae6b6a1b3c32867c293b08547a0941cf4059d2d567840ab6e"
					   "a526e3724ad59e715a3782ca656cbb739dfdf0c113a18f0dd62423d4edb60057fcaedbb852178d38f1b5a232842b4fc645cbfd97a8cac0b094b"
					   "870064302dcdf23df2c9e9f736d93409cbb8ce9ab3",
					   272);

	m = bignum_set_hex(
		NULL,
		"c462c7cdd79b7604246a0cd97c017700feb25908656b4733353af8119ecfa0212e4bd24304edd566adb5c1e9daa40894290a9e2e20d523bfdb5a2603409b312cba"
		"43d567a27118c15d4bb2f3867a7ba7594e02859850b77b929823049d43573a881948d674e95c7427e2d04d4ed81b5f4de21e0d5904c8e0359c99d4bdc901a4",
		256);

	r = bignum_modsqr(NULL, NULL, a, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex,
		"0x2bab348824111bdd7293300429a058c584cf91663ba390868bbde9268472ef9f6d704496983af27460a69fe2b6ad77abf9f5f0cc322a8889677773d512cfe053"
		"9ce4ea31721763cbe1a24e7f5077b379f60d88079ae33caf3b382cc01639d0afd5e6e9a520f90e428706b83aacfaa6de307513eb6563cc8432d072f61a67baed",
		258);
	status += CHECK_VALUE(result, 258);

	bignum_delete(a);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL,
					   "c362d5ca2d5301a194b9405d99c99b1dd37c69904b2f780cf11f1e1411607c161bc9e6c136ffb1756cc9e631bd217606f3b55cc6a9cf7"
					   "a7d3ed132af972e9563375ae1732996f897cd9ab1f308dcb29328518c34b3174bb1e3bc0066f9cbb7770ed0815cdc1f38ca344e91baae"
					   "c79d8173d2fe6ba37fb8745d505fe4e1504b59",
					   256);

	m = bignum_set_hex(
		NULL,
		"c95943186c7567fe8cd1bb4f07e7c659475fd9f38217571af20dfe7e4666d86286bc5b2bb013197f9b1c452c69a95bb7e450cf6e45d46e452282d5d2826978e06c"
		"52c7ca204869e8d1b1fac4911e3aef92c7b2d7551ebd8c6fe0365fad49e275cc2949a124385cadc4ace24671c4fe86a849de07c6fafacb312f55e9f3c79dcb",
		256);

	r = bignum_modsqr(NULL, NULL, a, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex,
		"0x6b22c74349a1beb6700d8cd1d54e88347107a8445ee84aadbc26330a4705da83cd454c7d03b7656d18e307db0b5944c6c7432ea90f6cbb887b1c394fd0be9b6a"
		"d721fd2569a1428936323f9b11921a4d1a17e4d2b76e8b6190448bc445bb294a0b5550d83da43cecc808a819e4ee4bd77793d00a1e225b811038f447ab167de7",
		258);
	status += CHECK_VALUE(result, 258);

	bignum_delete(a);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	return status;
}

int32_t bignum_modmul_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *b = NULL, *m = NULL, *r = NULL;
	char hex[512] = {0};

	// ------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL, "6b18497fed9befdf22a01d988d34213f6687d8a96e86c188dea4172e7c6095a0d18d3c86c0f5a1af9c6e3aaeb6baac2a510930b3ed06ec78ec2e12b",
		119);
	b = bignum_set_hex(NULL, "1a058d99397db0d209f01212dd4023ae01b15da04fe62d1f76f21622b2695558c67d706c535ca7f19b36f8ef2d508ffd6cf6fcf25e5",
					   107);
	m = bignum_set_hex(
		NULL,
		"c462c7cdd79b7604246a0cd97c017700feb25908656b4733353af8119ecfa0212e4bd24304edd566adb5c1e9daa40894290a9e2e20d523bfdb5a2603409b312cba"
		"43d567a27118c15d4bb2f3867a7ba7594e02859850b77b929823049d43573a881948d674e95c7427e2d04d4ed81b5f4de21e0d5904c8e0359c99d4bdc901a4",
		256);

	r = bignum_modmul(NULL, NULL, a, b, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status +=
		CHECK_HEX(hex,
				  "0xae2ca2ce7addaee2e2b7752e286b2bb6a58b51cfbed5c924f00398e59ec36fe6341cd83da43a33a12410f45f6228079c4aeb3912be87e2e81f"
				  "a1799151bfa0fea29873097475b2c3efa312145d0bf7e51b2a7c9bc961a4f4dcf0c883ff90b919b87c21099fba40257645be31f95a3a277",
				  227);
	status += CHECK_VALUE(result, 227);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"6c484e3c6b530dcd3644b19fee66c41c7c2c1dbcde574d87ee13cabef9dccbe5b41e25c32c6a56df23f2e87176afd28249e5fcb918723707fca94d7e2c9623a349"
		"3d395db802a1b49d550f52c29666f785652fe81afcab00a60a5b50cbf523cd13dfa06d5a5b0809c68ff7264a2cb35b8d52284172c62ee658e8417e6",
		249);
	b = bignum_set_hex(
		NULL,
		"1b4fc753d0530bd07094bae09a02b1ea684fb4e8519086b1e2ed9d59af011f61d1b94ffca6f354a5b428417b328bb1e8af3f6c7ac9121dae58de9f1dcbaa9c73a3"
		"57f408b870e62b0c7db1a72c4c440f2e6fe90b199b9dab29fc23927190d3f2bf8a7ee926a152e64474283695614ad696c85ea547f5f51d02d1b823e3",
		250);
	m = bignum_set_hex(
		NULL,
		"c462c7cdd79b7604246a0cd97c017700feb25908656b4733353af8119ecfa0212e4bd24304edd566adb5c1e9daa40894290a9e2e20d523bfdb5a2603409b312cba"
		"43d567a27118c15d4bb2f3867a7ba7594e02859850b77b929823049d43573a881948d674e95c7427e2d04d4ed81b5f4de21e0d5904c8e0359c99d4bdc901a4",
		256);

	r = bignum_modmul(NULL, NULL, a, b, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex,
						"0xb456ccf9d066dcf4247a21c7f3820e324ac9cf004cecf8dd1f6c3aa40c2a33e24c423e97190fc71bb9fec21d36c5a687065a7877237a2"
						"a05e64cabfb3b20bfff0b1f5ef2e9adb7edcd7140d1047b0919a2c770579ab44a08e5ad9f63a06f90ec7d5885b91de5e524b2e1879376"
						"09b4b81d40a0b33e31a48d7b9868add75286a6",
						258);
	status += CHECK_VALUE(result, 258);

	bignum_delete(a);
	bignum_delete(b);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	return status;
}

int32_t bignum_modexp_tests(void)
{
	int32_t status = 0;
	uint32_t result = 0;

	bignum_t *a = NULL, *p = NULL, *m = NULL, *r = NULL;
	char hex[512] = {0};

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "86b49", 5);
	p = bignum_set_hex(NULL, "2", 1);
	m = bignum_set_hex(NULL, "30d26ecb", 8);

	r = bignum_modexp(NULL, NULL, a, p, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x208f8aa0", 10);
	status += CHECK_VALUE(result, 10);

	bignum_delete(a);
	bignum_delete(p);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "17591bb", 7);
	p = bignum_set_hex(NULL, "6", 1);
	m = bignum_set_hex(NULL, "30d26ecb", 8);

	r = bignum_modexp(NULL, NULL, a, p, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x27308229", 10);
	status += CHECK_VALUE(result, 10);

	bignum_delete(a);
	bignum_delete(p);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(NULL, "21292626", 8);
	p = bignum_set_hex(NULL, "d", 1);
	m = bignum_set_hex(NULL, "30d26ecb", 8);

	r = bignum_modexp(NULL, NULL, a, p, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(hex, "0x2bdf498f", 10);
	status += CHECK_VALUE(result, 10);

	bignum_delete(a);
	bignum_delete(p);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"ead8c5a451541c50cab74de530c89376d9a55c723e0cac3c84b25f0093c08a2961e49ab48966361c42c9f99111587252d98395b76788400d75c66ef208ea2767a2"
		"8d6f8dc3a859f39c95765d57f139e7fc14f47c908c62df051e7216d379f52028843b4d82ef49133cce8fe671ae179423ac8da5be43b01caaf425cd969300cd",
		256);
	p = bignum_set_hex(
		NULL,
		"8de689aef79eba6b20d7debb8d146541348df2f259dff6c3bfabf5517c8caf0473866a03ddbd03fc354bb00beda35e67f342d684896bf8dbb79238a6929692b1a8"
		"7f58a2dcba596fe1a0514e3019baffe1b580fc810bd9774c00ab0f37af78619b30f273e3bfb95daac34e74566f84bb8809be7650dec75a20be61b4f904ed4e",
		256);
	m = bignum_set_hex(
		NULL,
		"c95943186c7567fe8cd1bb4f07e7c659475fd9f38217571af20dfe7e4666d86286bc5b2bb013197f9b1c452c69a95bb7e450cf6e45d46e452282d5d2826978e06c"
		"52c7ca204869e8d1b1fac4911e3aef92c7b2d7551ebd8c6fe0365fad49e275cc2949a124385cadc4ace24671c4fe86a849de07c6fafacb312f55e9f3c79dcb",
		256);

	r = bignum_modexp(NULL, NULL, a, p, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex,
		"0x5150fb769d5c5d341aaf56639a7bcc77c415fe46439938a2190283409692f29cd080bfe3433005d98d24718a03a3553c8560c5e9c8ed0f53b8945eb18290e1c1"
		"a83d919302510f66dd89b58acc2de79ad54b8a30d3e1019d4d222556beefca0821b094ecf104b5e4cfce69d2d520d2abf54f3e393d25ed3d27e8c2e3ca2e5ff9",
		258);
	status += CHECK_VALUE(result, 258);

	bignum_delete(a);
	bignum_delete(p);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"855144760f2be2f2038d8ff628f03a902ae2e07736f2695ec980f84a1781665ab65e2b4e53d31856f431a32fd58d8a7727acee54cc54a62161b035c0293714ca29"
		"4e2161ea4a48660bf084b885f504ad23ea338030460310bd19186be9030ab5136f09fe6a9223962bce385aaaf9c39fe6ed6d005fa96163fe15cdfa08fc914d",
		256);
	p = bignum_set_hex(
		NULL,
		"bb552be12c02ae8b9e90c8beb5689ffefe3378d2c30f12a6d14496250ecce30317c642857535a741642c3df689a8d71a276d247ed482b07b50135357da6143ac2f"
		"5c74f6c739c5ff6ada21e1ab35439f6445a1019d6b607950bffb0357c6009a2bfc88cd7f4f883dc591d4eb45b1d787e85aba5c10ee4fe05ea47bf556aec94d",
		256);
	m = bignum_set_hex(
		NULL,
		"dcc24236a1bb94c71d9ec162a6aa4697b932717e82b667cad08b6bd1bbcbddf7cd167b7458de2b0b780486b39574e749d6405f9ede774a021d6b547271523e9e84"
		"a6fdd3a98315607ccf93356f54daa9c75e1e311e1672d0dc163be13f9ed6762f7dd301f5b0a1bb2398b608f40ac357ae34fc8a87d4fef3b961cbdb806d9061",
		256);

	r = bignum_modexp(NULL, NULL, a, p, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex,
		"0xbbad67352704a6321809f742826bf3d1c31c0ad057bf81432abeb30dc9913c896c03e69eb1cde6b78ffcb320c4625bd38ef23a08d6c64dc86aec951b72d74b09"
		"7e209ce63092959894614e3865a6153ec0ff6fda639e44071a33763f6b18edc1c22094c3f844f04a86d414c4cb618e9812991c61289360c7ba60f190f75038d0",
		258);
	status += CHECK_VALUE(result, 258);

	bignum_delete(a);
	bignum_delete(p);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	a = bignum_set_hex(
		NULL,
		"b4fde2908745ff92cc5826a27dcfdda09e8fffee681844fa4c7f1354d946d5d84e0e0c7a4a4cb20943d9c73dd707ca47d796945d6f6b55933b615e2c522f5dfc33"
		"e0652917b4809bab86f4fa56b32b746c177764895492d0a6a699812b2827fe701d40ef7effd78ea8efe1cac15ff74a295a09614bf04cae1a5017872ba22efe",
		256);
	p = bignum_set_hex(
		NULL,
		"a5524b41dfc6b570df1d8f6633ac7777c1131abe3a99c6166b0d29d3b8883c41b00a0c53cdd6f42820bf05c810b6ec53e77a8c1b9344ea0c91d4f410a2f204c369"
		"f3db33bf8c88217fc2cf802a9d9bce8119242d8e781875b85431be170076498c0963574ee423551aec9557e2fc672ab1ab5d0cbb1c400535df9481e7934d8f",
		256);
	m = bignum_set_hex(
		NULL,
		"88f3c87ac5e3272a21b8a858da640d6939fb8113a95412c38663a0f352686d69a5d7927e60b484b9fcb8ef12978fe25ff2ebc9b61c5450e04222ef20ba3cbbdc5e"
		"c45581ce0f58e10be7bb9de7fa08752303a7a1db23b2ac9c6692ec63bf09ecd6639e06c5491ba568ea886620d71da32d329615f0e1443a75d09ae35b8a2d7f",
		256);

	r = bignum_modexp(NULL, NULL, a, p, m);

	memset(hex, 0, 512);
	result = bignum_get_hex(r, hex, 512);

	status += CHECK_HEX(
		hex,
		"0x292f0b39ca0f1c850b1a00cffd2d54924fcd5fc7e7504c9d593e6c0ff74760b1f4bdd81679fe06c50248336f3108c593fa111072ee87d0fcc89a63243a1dc890"
		"44503663eee9bc18f51c3e0193d9108303e12ac90ff78f6ec752a4386af09c42db524a7cbe9a3d4fcccd56c34d283bcc9debc17158b5fe8df0c1888a9841bf8f",
		258);
	status += CHECK_VALUE(result, 258);

	bignum_delete(a);
	bignum_delete(p);
	bignum_delete(m);
	bignum_delete(r);

	// ------------------------------------------------------------------------

	return status;
}

int main()
{
	return bignum_modadd_tests() + bignum_modsub_tests() + bignum_modsqr_tests() + bignum_modmul_tests() + bignum_modexp_tests();
}
