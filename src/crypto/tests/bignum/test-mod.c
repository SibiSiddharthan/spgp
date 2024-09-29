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

int main()
{
	return bignum_modadd_tests() + bignum_modsub_tests() + bignum_modsqr_tests() + bignum_modmul_tests();
}
