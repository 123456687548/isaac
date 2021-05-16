#include <Windows.h>
#include <stdio.h>
#include <iostream>

#include "util.h"

enum ECurseType {
	NONE = 0,
	DARKNESS = 1,
	LABYRINTH = 2,
	LOST = 4,
	UNKNOWN = 8,
	MAZE = 32,
	BLIND = 64
};

#ifdef _DEBUG
FILE* f;
#endif

const char* szIsaacModule = "isaac-ng.exe";

typedef void(__fastcall* startStage)(uintptr_t);
startStage oStartStage = nullptr;

BYTE oStartStageBytes[10];
uintptr_t startStageAddress;
uintptr_t blindCursePatchLocation;

BYTE oDebugConsoleCheckBytes[2];
uintptr_t canUnlockAchivementsAddress;
bool unlockConsole = false;

uintptr_t debugConsoleKeyEventAddress;

BYTE oDebugConsoleAchivementCheckBytes[6];
uintptr_t debugConsoleAchivementCheckAddress;
uintptr_t debugConsoleAchivementCheckAddressRet;
uintptr_t gameObj;

uintptr_t worldObj;
int* curse = 0;

bool init = false;

DWORD WINAPI dllThread(HMODULE hModule);
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
void startup();
void cleanup();
void hookFunctions();
void __fastcall hkStartStage(uintptr_t obj);
void hkDebugConsoleAchivementCheck();

DWORD WINAPI dllThread(HMODULE hModule) {
	startup();
	hookFunctions();

	while (!GetAsyncKeyState(VK_END)) {
		if (init && *curse != 0) {
			if ((*curse & ECurseType::BLIND) == ECurseType::BLIND) {
				std::cout << "BLIND" << std::endl;
				*curse = 0;
			}
		}

		if (GetAsyncKeyState(VK_DELETE) & 1 && init) {
			if ((*curse & ECurseType::LABYRINTH) != ECurseType::LABYRINTH) {
				*curse = 0;
			}
		}

		if (GetAsyncKeyState(VK_F1) & 1) {
			unlockConsole = !unlockConsole;
			if (unlockConsole) {
				//util::mem::Patch((BYTE*)canUnlockAchivementsAddress, (BYTE*)"\x74", 1);
				util::mem::Patch((BYTE*)debugConsoleKeyEventAddress, (BYTE*)"\x0F\x85", 2);
			}
			else {
				//util::mem::Patch((BYTE*)canUnlockAchivementsAddress, (BYTE*)"\x75", 1);
				util::mem::Patch((BYTE*)debugConsoleKeyEventAddress, (BYTE*)"\x0F\x84", 2);
			}

			std::cout << "Can get Achivements: " << std::dec << !unlockConsole << std::endl;
		}
		if (GetAsyncKeyState(VK_F2) & 1) {
			//memcpy(oDebugConsoleAchivementCheckBytes, (char*)debugConsoleAchivementCheckAddress, 6);
			//util::mem::PlaceJMP((BYTE*)debugConsoleAchivementCheckAddress, (DWORD)hkDebugConsoleAchivementCheck, 0x6);
		}
			
		if (GetAsyncKeyState(VK_INSERT) & 1) {
			util::mem::NOP((BYTE*)blindCursePatchLocation, 4);
			//util::mem::Patch((BYTE*)blindCursePatchLocation, (BYTE*)"\x90\x90\x90\x90", 4);
			std::cout << "patching blindCursePatchLocation: 0x" << std::hex << blindCursePatchLocation << std::endl;
		}
		Sleep(100);
	}

	cleanup();

	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

void __fastcall hkStartStage(uintptr_t obj) {
	worldObj = obj;
	//std::cout << "hook" << std::endl;
	//std::cout << "pWorldObj: 0x" << std::hex << obj << std::endl;
	curse = (int*)(obj + 0xC);

	//std::cout << "pCurse: 0x" << std::hex << curse << std::endl;

	if (!init) {
		std::cout << "pWorldObj: 0x" << std::hex << obj << std::endl;
		init = true;
	}

	oStartStage(obj);
}

void __declspec(naked) hkDebugConsoleAchivementCheck() {
	__asm {
		mov al, 0
		mov gameObj, ecx
		jmp[debugConsoleAchivementCheckAddressRet]
	}
}

void startup() {
#ifdef _DEBUG
	AllocConsole();
	freopen_s(&f, "CONOUT$", "w", stdout);
#endif

	startStageAddress = (uintptr_t)util::mem::patternScanNew(szIsaacModule, "\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xD9\x89\x5D\xE4\x8B\x00\x00\x00\x00\x00\x89\x4D\xE0", "xxxxxxxxxxxxxxx?????xxx", -0x1F);
	blindCursePatchLocation = startStageAddress + 0x60A;
	canUnlockAchivementsAddress = (uintptr_t)util::mem::patternScanNew(szIsaacModule, "\x80\xBE\xDD\x86\x02\x00\x00\x74\x35\x80\x7D\x08\x00", "xxxxxxxxxxxxx", 0);
	debugConsoleKeyEventAddress = (uintptr_t)util::mem::patternScanNew(szIsaacModule, "\x0F\x84\x00\x00\x00\x00\x83\x38\x02\x75\x21", "xx????xxxxx");
	//debugConsoleAchivementCheckAddress = (uintptr_t)util::mem::patternScanNew(szIsaacModule, "\x8D\x91\x04\x8A\x06\x00\x8A\x81\xDD\x86\x02\x00\xF3\x0F\x10", "xxxxxxxxxxxxxxx", 0x6);
	//debugConsoleAchivementCheckAddressRet = debugConsoleAchivementCheckAddress + 0x6;

	std::cout << "startStageAddress: 0x" << std::hex << startStageAddress << std::endl;
	std::cout << "blindCursePatchLocation: 0x" << std::hex << blindCursePatchLocation << std::endl;
	std::cout << "debugConsoleCheckAddress: 0x" << std::hex << canUnlockAchivementsAddress << std::endl;
	std::cout << "debugConsoleKeyEventAddress: 0x" << std::hex << debugConsoleKeyEventAddress << std::endl;
	std::cout << "debugConsoleAchivementCheckAddress: 0x" << std::hex << debugConsoleAchivementCheckAddress << std::endl;
	std::cout << "hkDebugConsoleAchivementCheck: 0x" << std::hex << hkDebugConsoleAchivementCheck << std::endl;
}

void cleanup() {
	//release hook
	util::mem::Patch((BYTE*)startStageAddress, oStartStageBytes, 10);

#ifdef _DEBUG
	if (f != 0) {
		fclose(f);
		FreeConsole();
	}
#endif
}

void hookFunctions() {
	memcpy(oStartStageBytes, (char*)startStageAddress, 10);
	oStartStage = (startStage)util::mem::TrampHook((char*)startStageAddress, (char*)hkStartStage, 10);

	//memcpy(oDebugConsoleAchivementCheckBytes, (char*)debugConsoleAchivementCheckAddress, 6);
	//util::mem::PlaceJMP((BYTE*)debugConsoleAchivementCheckAddress, (DWORD)hkDebugConsoleAchivementCheck, 0x6);
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