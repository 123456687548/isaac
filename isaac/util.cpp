#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "util.h"

uintptr_t util::mem::GetModuleBaseAddress(DWORD procId, const char* modName) {
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry)) {
			do {
				if (!_stricmp(modEntry.szModule, modName)) {
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

void util::mem::Patch(BYTE* dst, BYTE* src, unsigned int size) {
	DWORD oProt;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oProt);
	memcpy(dst, src, size);
	VirtualProtect(dst, size, oProt, &oProt);
}

bool util::mem::Hook(char* src, char* dst, int length) {
	if (length < 5) return false;
	DWORD oProt;
	VirtualProtect(src, length, PAGE_EXECUTE_READWRITE, &oProt);
	memset(src, 0x90, length);
	uintptr_t relAddy = (uintptr_t)(dst - src - 5);
	*src = (char)0xE9;
	*(uintptr_t*)(src + 1) = (uintptr_t)relAddy;
	VirtualProtect(src, length, oProt, &oProt);
}

char* util::mem::TrampHook(char* src, char* dst, int length) {
	if (length < 5) return nullptr;

	char* gateway = (char*)VirtualAlloc(0, length + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!gateway) {
		return nullptr;
	}
	memcpy(gateway, src, length);
	uintptr_t jumpAddy = (uintptr_t)(src - gateway - 5);
	*(gateway + length) = (char)0xE9;
	*(uintptr_t*)(gateway + length + 1) = jumpAddy;
	if (Hook(src, dst, length)) {
		return gateway;
	}
	else {
		return nullptr;
	}
}

DWORD util::mem::patternScanNew(const char* module, const char* pattern, const char* mask, int offset) {
	MEMORY_BASIC_INFORMATION mbi{ 0 };
	DWORD protectflags = (PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS);

	DWORD patternLength = (DWORD)strlen(mask);

	MODULEINFO moduleInfo;
	HMODULE moduleHandle = GetModuleHandle(module);

	if (moduleHandle && GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(moduleInfo))) {
		for (char* c = (char*)moduleInfo.lpBaseOfDll; c != (char*)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage; c++) {
			if (VirtualQuery((LPCVOID)c, &mbi, sizeof(mbi))) {
				if (mbi.Protect & protectflags || !(mbi.State & MEM_COMMIT)) {
					c += mbi.RegionSize;
					continue;
				}
				for (DWORD k = (DWORD)mbi.BaseAddress; k < (DWORD)mbi.BaseAddress + mbi.RegionSize - patternLength; k++) {
					for (DWORD j = 0; j < patternLength; j++) {
						if (mask[j] != '?' && pattern[j] != *(char*)(k + j)) {
							break;
						}
						if (j + 1 == patternLength && (char*)k != pattern) {
							return k + offset;
						}
					}
				}
				c = (char*)mbi.BaseAddress + mbi.RegionSize;
			}
		}
		return NULL;
	}
}
