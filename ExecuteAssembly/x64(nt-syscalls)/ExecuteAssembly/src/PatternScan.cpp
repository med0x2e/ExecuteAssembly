#include "PatternScan.h"
#include "PEB.h"
#include "syscalls.h"


template <class AIterator, class BIterator>
void Check(PBYTE base, AIterator buf_start, AIterator buf_end, BIterator pat_start, BIterator pat_end, LPSTR* PE_Header_Addresses, size_t* _len) {

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

	MEMORY_BASIC_INFORMATION memInfo;
	SIZE_T returnedBytes = NULL;

	*(_len) = 0;

	LPSTR* PE_Header_Addresses = (char **)malloc(sizeof(char*) * NUMBER_OF_ADDRS);
	string _pattern = pattern;

	NTSTATUS status;
	SYSTEM_INFO _sysInfo;
	GetSystemInfo(&_sysInfo);
	PBYTE pCurrentAddr = (PBYTE)_sysInfo.lpMinimumApplicationAddress;
	PBYTE pMaximumAddr = (PBYTE)_sysInfo.lpMaximumApplicationAddress;

	while (pCurrentAddr < pMaximumAddr) {

		status = NtQueryVirtualMemory(hProcess, (PVOID)pCurrentAddr, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), &returnedBytes);

		if (NT_SUCCESS(status) && returnedBytes > 0) {

			vector<TCHAR> _bytes;

			if ((memInfo.State == MEM_COMMIT && (memInfo.Type == MEM_MAPPED || memInfo.Type == MEM_PRIVATE)) &&
				(memInfo.Protect == PAGE_READWRITE || memInfo.Protect == PAGE_EXECUTE_READWRITE || memInfo.Protect == PAGE_EXECUTE_READ)) {

				DWORD_PTR _bytesCount;
				_bytes.resize(memInfo.RegionSize);

				status = NtReadVirtualMemory(hProcess, pCurrentAddr, (PVOID)&_bytes[0], memInfo.RegionSize, &_bytesCount);
				if (NT_SUCCESS(status)) {
					_bytes.resize(_bytesCount);
					Check(pCurrentAddr, _bytes.begin(), _bytes.end(), _pattern.begin(), _pattern.end(), PE_Header_Addresses, _len);
				}
			}

			pCurrentAddr += memInfo.RegionSize;
		}
		
	} 

	return PE_Header_Addresses;
}