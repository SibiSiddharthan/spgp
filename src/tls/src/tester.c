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
	uint8_t buffer[65536];

	while (1)
	{
		void *record = NULL;
		buffer_t print_buffer = {0};

		memset(buffer, 0, 65536);
		status = recv(handler, (char *)buffer, 65536, 0);
		printf("%llu %d %d\n", handler, status, WSAGetLastError());

		if (status == 0 || status == -1)
		{
			printf("Bye!.\n");
			break;
		}

		tls_record_read(&record, buffer, status);

		memory_buffer_init(&print_buffer, 4096);

		tls_record_print(record, &print_buffer, 0);
		printf("%.*s", print_buffer.pos, print_buffer.data);

		memory_buffer_free(&print_buffer);
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
	// printf("%llu %d\n", (intptr_t)socket, WSAGetLastError());

	status = bind(listener, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	// printf("%d %d\n", status, WSAGetLastError());

	status = listen(listener, 10);
	// printf("%d %d\n", status, WSAGetLastError());

	SOCKET handler;
	while (1)
	{
		handler = accept(listener, NULL, NULL);
		printf("Got a client %llu %d\n", (intptr_t)handler, WSAGetLastError());
		CreateThread(NULL, 0, handle_requests, (PVOID)handler, 0, NULL);
	}

	closesocket(listener);

	WSACleanup();
}