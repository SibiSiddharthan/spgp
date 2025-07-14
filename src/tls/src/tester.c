#ifdef _WIN32
#	define WIN32_LEAN_AND_MEAN
#	define _WINSOCK_DEPRECATED_NO_WARNINGS
#	define _CRT_SECURE_NO_WARNINGS

#	pragma comment(lib, "Ws2_32.lib")

#	include <Windows.h>
#	include <WinSock2.h>
#	include <WS2tcpip.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <tls.h>


DWORD handle_requests(PVOID socket)
{
	SOCKET handler = (SOCKET)socket;
	int status;
	uint8_t buffer[1024];
	char rbuffer[65536], sbuffer[65536];

	while (1)
	{
		memset(buffer, 0, 1024);
		status = recv(handler, (char *)buffer, 1024, 0);
		printf("%llu %d %d\n", handler, status, WSAGetLastError());

		if (status == 0)
		{
			printf("Bye!.\n");
			break;
		}

		uint8_t content_type = buffer[0];
		uint16_t record_version = buffer[1] * 256 + buffer[2];
		uint16_t record_length = buffer[3] * 256 + buffer[4];

		printf("Content Type: %hhu\n", content_type);
		printf("Record Version: %hu\n", record_version);
		printf("Record Length: %hu\n", record_length);

		if (content_type == handshake)
		{
			size_t index = 5;

			uint8_t handshake_type = buffer[index];
			index += 1;

			uint32_t handshake_length = buffer[index] * 65536 + buffer[index + 1] * 256 + buffer[index + 2];
			index += 3;

			printf("Handshake Type: %hhu\n", handshake_type);
			printf("Handshake length: %u\n", handshake_length);

			uint16_t protocol_version = buffer[index] * 256 + buffer[index + 1];
			index += 2;

			printf("Protocol Version: %hu\n", protocol_version);

			// Skip random
			index += 32;

			uint8_t session_id_length = buffer[index];
			index += 1;

			// Skip session id
			index += session_id_length;

			uint16_t cipher_suites_length = buffer[index] * 256 + buffer[index + 1];
			index += 2;

			printf("Cipher Suites Length: %hu\n", cipher_suites_length);
			printf("Cipher Suites\n");
			for (size_t i = 0; i < cipher_suites_length; i += 2)
			{
				printf("{%02hhx, %02hhx}: %s\n", buffer[index + i], buffer[index + i + 1], get_cipher_str(&buffer[index + i]));
			}

			index += cipher_suites_length;

			uint8_t compression_method_length = buffer[index];
			index += 1;

			uint8_t compression_method = buffer[index];
			index += compression_method_length;

			printf("Compression Method Length : %hhu\n", compression_method_length);
			printf("Compression Method : %hhu\n", compression_method);

			uint16_t extensions_length = buffer[index] * 256 + buffer[index + 1];
			index += 2;

			printf("Extensions Length: %hu\n", extensions_length);

			while (index < status)
			{
				uint16_t extension_type = buffer[index] * 256 + buffer[index + 1];
				index += 2;

				printf("\n");
				printf("Extension Type: %hu\n", extension_type);

				uint16_t extension_data_length = buffer[index] * 256 + buffer[index + 1];
				index += 2;

				printf("Extension Data Length: %hu\n", extension_data_length);
				printf("\n");

				if (extension_type == server_name)
				{
					printf("Server Name Extension\n");
					uint16_t server_names_list_length = buffer[index] * 256 + buffer[index + 1];
					index += 2;

					printf("Server Name List Length: %hu\n", server_names_list_length);

					for (size_t i = 0; i < server_names_list_length;)
					{
						uint8_t name_type = buffer[index + i];
						i += 1;

						uint16_t name_length = buffer[index + i] * 256 + buffer[index + i + 1];
						i += 2;

						printf("Name Type: %hhu\n", name_type);
						printf("Name Length: %hu\n", name_length);

						char name[16] = {0};
						memcpy(name, &buffer[index + i], name_length);

						printf("Name : %s\n", name);

						i += name_length;
					}

					index += server_names_list_length;
				}
				else if (extension_type == max_fragment_length)
				{
					printf("Max Fragment Length Extension\n");
					uint16_t fragment_length = buffer[index] * 256 + buffer[index + 1];
					index += 2;

					printf("Max Fragment Length: %hu\n", fragment_length);
				}
				else if (extension_type == status_request)
				{
					printf("Status Request Extension\n");
					uint8_t status_type = buffer[index];
					index += 1;

					printf("Status Type: %hhu\n", status_type);

					uint16_t responder_id_length = buffer[index] * 256 + buffer[index + 1];
					index += 2;

					printf("Responder ID Length: %hu\n", responder_id_length);
					index += responder_id_length;

					uint16_t status_extension_length = buffer[index] * 256 + buffer[index + 1];
					index += 2;

					printf("Status Extension Length: %hu\n", responder_id_length);
					index += status_extension_length;
				}
				else if (extension_type == supported_groups)
				{

					printf("Supported Groups Extension\n");

					uint16_t group_length = buffer[index] * 256 + buffer[index + 1];
					index += 2;

					printf("Group Length: %hu\n", group_length);

					for (size_t i = 0; i < group_length;)
					{
						uint16_t curve = buffer[index + i] * 256 + buffer[index + i + 1];
						i += 2;

						printf("Curve: %hu\n", curve);
					}

					index += group_length;
				}
				else if (extension_type == ec_point_formats)
				{
					printf("EC Point Format Extension\n");
					uint8_t ec_length = buffer[index];
					index += 1;

					printf("EC Length: %hhu\n", ec_length);

					for (size_t i = 0; i < ec_length;)
					{
						uint8_t ec_type = buffer[index + i];
						i += 1;

						printf("EC Type: %hhu\n", ec_type);
					}

					index += ec_length;
				}
				else if (extension_type == signature_algorithms)
				{
					printf("Signature Algorithm Extension\n");

					uint16_t signauture_algorithms_length = buffer[index] * 256 + buffer[index + 1];
					index += 2;

					for (size_t i = 0; i < signauture_algorithms_length;)
					{
						uint16_t signature_algorithm = buffer[index + i] * 256 + buffer[index + i + 1];
						i += 2;

						printf("Signature Algorithm: %04hx\n", signature_algorithm);
					}

					index += signauture_algorithms_length;
				}
				else if (extension_type == padding)
				{
					printf("Padding\n");
					index += extension_data_length;
				}
				else if (extension_type == supported_versions)
				{
					printf("Supported Versions Extension\n");

					uint8_t version_length = buffer[index];
					index += 1;

					for (size_t i = 0; i < version_length;)
					{
						uint16_t version = buffer[index + i] * 256 + buffer[index + i + 1];
						i += 2;

						printf("Version: %hu\n", version);
					}

					index += version_length;
				}
				else if (extension_type == psk_key_exchange_modes)
				{
					printf("Pre-Shared Key Exchange Modes Extension\n");

					uint8_t psk_length = buffer[index];
					index += 1;

					for (size_t i = 0; i < psk_length;)
					{
						uint8_t psk_type = buffer[index + i];
						i += 1;

						printf("PSK Type: %hu\n", psk_type);
					}

					index += psk_length;
				}
				// else if (extension_type == key_share)
				//{
				//
				// }
				else
				{
					// Unknown extensions
					index += extension_data_length;
				}
			}
		}
	}

	closesocket(handler);
	return 0;
}

int main()
{
	int status;

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(10000);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	printf("%llu %d\n", (intptr_t)socket, WSAGetLastError());

	status = bind(listener, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	printf("%d %d\n", status, WSAGetLastError());

	status = listen(listener, 10);
	printf("%d %d\n", status, WSAGetLastError());

	SOCKET handler;
	while (1)
	{
		handler = accept(listener, NULL, NULL);
		printf("%llu %d\n", (intptr_t)handler, WSAGetLastError());

		printf("Got a client %llu\n", (intptr_t)handler);

		CreateThread(NULL, 0, handle_requests, (PVOID)handler, 0, NULL);
	}

	closesocket(listener);

	WSACleanup();
}