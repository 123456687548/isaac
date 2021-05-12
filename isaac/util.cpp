#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <assert.h>
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

bool util::mem::NOP(BYTE* dst, unsigned int size) {
	BYTE* nops = (BYTE*) calloc(size, sizeof(BYTE));

	if (nops == nullptr) return false;

	for (BYTE i = 0; i < size; i++) {
		nops[i] = '\x90';
	}

	Patch(dst, nops, size);

	free(nops);

	return true;
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
	return true;
}

char* util::mem::TrampHook(char* src, char* dst, int length) {
	assert(length >= 5);
	assert(src != 0);
	assert(dst != 0);
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


DWORD util::mem::patternScanNew(const char* module, const char* pattern, const char* mask) {
	return patternScanNew(module, pattern, mask, 0);
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

	return NULL;
}

void util::mem::PlaceJMP(BYTE* Address, DWORD jumpTo, DWORD length) {
	DWORD dwOldProtect, dwBkup, dwRelAddr;

	//give that address read and write permissions and store the old permissions at oldProtection
	VirtualProtect(Address, length, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// Calculate the "distance" we're gonna have to jump - the size of the JMP instruction
	dwRelAddr = (DWORD)(jumpTo - (DWORD)Address) - 5;

	// Write the JMP opcode @ our jump position...
	*Address = 0xE9;

	// Write the offset to where we're gonna jump
	//The instruction will then become JMP ff002123 for example
	*((DWORD*)(Address + 0x1)) = dwRelAddr;

	// Overwrite the rest of the bytes with NOPs
	//ensuring no instruction is Half overwritten(To prevent any crashes)
	for (DWORD x = 0x5; x < length; x++) {
		*(Address + x) = 0x90;
	}

	// Restore the default permissions
	VirtualProtect(Address, length, dwOldProtect, &dwBkup);
}