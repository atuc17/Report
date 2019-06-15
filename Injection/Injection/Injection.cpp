#include "pch.h"
#include <iostream>
#include <Windows.h>

BOOL SetDebugPrivilege(HANDLE hToken, LPCTSTR lpsz, BOOL Enable);
int main()
{
	HANDLE hToken = NULL;
	LPCSTR DllPath = "F:\\Injection\\x64\\Debug\\injector.dll";
	HANDLE hProcess;
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS |
		PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, 11120);  
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
		SetDebugPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	else
		printf("%d\n", GetLastError());
	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath) + 1,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath) + 1, NULL);
	LPVOID pr = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0,
		(LPTHREAD_START_ROUTINE)pr,
		pDllPath, 0, 0);
	if (hThread == NULL)
		printf("%d\n", GetLastError());
	WaitForSingleObject(hThread, INFINITE);
	std::cout << "Dll path allocated at: " << pDllPath;
	std::cin.get();
	VirtualFreeEx(hProcess, pDllPath, strlen(DllPath) + 1, MEM_RELEASE);
	CloseHandle(hProcess);
	/*
	HMODULE dll = LoadLibrary(L"F:\\Injection\\x64\\Debug\\injector.dll");
	if (dll == NULL)
	{
		printf("Dll could not be found\n");
		return 1;
	}
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "meconnect");
	if (addr == NULL)
	{
		printf("The function not found\n");
		return 1;
	}
	HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, 5888);
	if (handle == NULL)
	{
		printf("Cannot open hook\n");
		return 1;
	}
	printf("Program injection is successful\n");
	UnhookWindowsHookEx(handle);
	*/
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