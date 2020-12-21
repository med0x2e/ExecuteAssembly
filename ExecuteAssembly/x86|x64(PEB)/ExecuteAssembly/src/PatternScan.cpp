#include "PatternScan.h"
#include "PEB.h"

template <class AIterator, class BIterator>
void Check(LPSTR base, AIterator buf_start, AIterator buf_end, BIterator pat_start, BIterator pat_end, LPSTR* PE_Header_Addresses, size_t* _len) {

	size_t _count = *(_len);

	for (AIterator pos = buf_start; buf_end != (pos = search(pos, buf_end, pat_start, pat_end)); ++pos) {

		char* MZ_Addr = (char *)(base + (pos - buf_start));
		if (MZ_Addr != NULL) {
			*(PE_Header_Addresses + _count) = MZ_Addr;
			_count++;
		}
	}

	if (_count != 0)
		*(_len) = _count;

}

LPSTR* FindPattern(HANDLE hProcess, LPCSTR pattern, size_t* _len) {

	_PFNVirtualQueryEx VirtualQueryEx;
	_PFNReadProcessMemory ReadProcessMemory;
	ADDR kernel32_base = findModuleBase(_kernel32dll);

	VirtualQueryEx = (_PFNVirtualQueryEx)findExportAddr(kernel32_base, _VirtualQueryEx);
	ReadProcessMemory = (_PFNReadProcessMemory)findExportAddr(kernel32_base, _ReadProcessMemory);


	LPSTR lpAddr = NULL;
	MEMORY_BASIC_INFORMATION memInfo;

	*(_len) = 0;

	LPSTR* PE_Header_Addresses = (char **)malloc(sizeof(char*) * NUMBER_OF_ADDRS);
	string _pattern = pattern;


	for (lpAddr = NULL; VirtualQueryEx(hProcess, lpAddr, &memInfo, sizeof(memInfo)) == sizeof(memInfo); lpAddr += memInfo.RegionSize) {

		vector<char> _bytes;

		if ((memInfo.State == MEM_COMMIT && (memInfo.Type == MEM_MAPPED || memInfo.Type == MEM_PRIVATE)) &&
			(memInfo.Protect == PAGE_READWRITE || memInfo.Protect == PAGE_EXECUTE_READWRITE || memInfo.Protect == PAGE_EXECUTE_READ)) {

			DWORD_PTR _bytesCount;
			_bytes.resize(memInfo.RegionSize);
			ReadProcessMemory(hProcess, lpAddr, &_bytes[0], memInfo.RegionSize, &_bytesCount);
			_bytes.resize(_bytesCount);
			Check(lpAddr, _bytes.begin(), _bytes.end(), _pattern.begin(), _pattern.end(), PE_Header_Addresses, _len);
		}
	}

	return PE_Header_Addresses;
}