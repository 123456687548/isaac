#include <Windows.h>
#include <stdio.h>
#include <iostream>

#include "util.h"

typedef void(__fastcall* startStage)(uintptr_t);
startStage oStartStage = nullptr;

uintptr_t startStageAddress = 0x122F6E0;//0x7ef6e0;

int* curse = 0;
uintptr_t worldObj;
BYTE oStartStageBytes[10];

bool interrupt = false;


enum curseType {
	NONE = 0,
	DARKNESS = 1,
	LABYRINTH = 2,
	LOST = 4,
	UNKNOWN = 8,
	MAZE = 32,
	BLIND = 64
};

void __fastcall hkStartStage(uintptr_t obj) {
	worldObj = obj;
	//std::cout << "hook" << std::endl;
	//std::cout << "pWorldObj: 0x" << std::hex << obj << std::endl;
	curse = (int*)(obj + 0xC);

	//std::cout << "pCurse: 0x" << std::hex << curse << std::endl;
	interrupt = true;
	oStartStage(obj);
}

DWORD WINAPI dllThread(HMODULE hModule) {
#ifdef _DEBUG
	FILE* f;
	AllocConsole();
	freopen_s(&f, "CONOUT$", "w", stdout);
#endif

	startStageAddress = (uintptr_t)util::mem::patternScanNew("isaac-ng.exe", "\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xD9\x89\x5D\xE4\x8B\x00\x00\x00\x00\x00\x89\x4D\xE0", "xxxxxxxxxxxxxxx?????xxx", -0x1F);

	memcpy(oStartStageBytes, (char*)startStageAddress, 10);
	oStartStage = (startStage)util::mem::TrampHook((char*)startStageAddress, (char*)hkStartStage, 10);

	while (!GetAsyncKeyState(VK_END)) {
		if (interrupt && *curse != 0) {
			if (*curse == curseType::BLIND) {
				std::cout << "BLIND" << std::endl;
				*curse = 0;
			}
			interrupt = false;
		}
		Sleep(100);
	}

	util::mem::Patch((BYTE*)startStageAddress, oStartStageBytes, 10);

#ifdef _DEBUG
	if (f != 0) {
		fclose(f);
		FreeConsole();
	}
#endif
	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hModule);
		HANDLE hThread = nullptr;
		hThread = CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)dllThread, hModule, NULL, nullptr);
		if (hThread) {
			CloseHandle(hThread);
		}
	}
	return TRUE;
}
