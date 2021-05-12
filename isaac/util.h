#pragma once
namespace util {
	namespace mem {
		DWORD patternScanNew(const char* module, const char* pattern, const char* mask, int offset);
		DWORD patternScanNew(const char* module, const char* pattern, const char* mask);
		uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName);
		void Patch(BYTE* dst, BYTE* src, unsigned int size);
		bool NOP(BYTE* dst, unsigned int size);
		bool Hook(char* src, char* dst, int length);
		char* TrampHook(char* src, char* dst, int length);
		void PlaceJMP(BYTE* Address, DWORD jumpTo, DWORD length);
	}
}
