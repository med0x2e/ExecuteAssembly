#include "PEModuleHelper.h"

#include <windows.h>
#include <winternl.h>
#include "PatternScan.h"
#include "PEB.h"
#include "syscalls.h"


namespace PEModuleHelper {

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWCH   Buffer;
	} UNICODE_STRING;
	
	typedef UNICODE_STRING *PUNICODE_STRING;

	typedef struct _PEB_LDR_DATA
	{
		ULONG           Length;
		BOOLEAN         Initialized;
		PVOID           SsHandle;
		LIST_ENTRY      InLoadOrderModuleList;
		LIST_ENTRY      InMemoryOrderModuleList;
		LIST_ENTRY      InInitializationOrderModuleList;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _LDR_MODULE
	{
		LIST_ENTRY      InLoadOrderModuleList;
		LIST_ENTRY      InMemoryOrderModuleList;
		LIST_ENTRY      InInitializationOrderModuleList;
		PVOID           BaseAddress;
		PVOID           EntryPoint;
		ULONG           SizeOfImage;
		UNICODE_STRING  FullDllName;
		UNICODE_STRING  BaseDllName;
		ULONG           Flags;
		SHORT           LoadCount;
		SHORT           TlsIndex;
		LIST_ENTRY      HashTableEntry;
		ULONG           TimeDateStamp;
	} LDR_MODULE, *PLDR_MODULE;

	void UnlinkModuleWithStr(LPSTR szModuleStr)
	{
		DWORD dwPEB = 0, dwOffset = 0;
		PLIST_ENTRY pUserModuleHead, pUserModule;
		PPEB_LDR_DATA pLdrData;
		PLDR_MODULE pLdrModule = NULL;
		PUNICODE_STRING lpModule = NULL;
		char szModuleName[512];
		int i = 0, n = 0;
		#ifndef _WIN64
		_asm
		{
			pushad
			mov eax, fs: [48]
			mov dwPEB, eax
			popad
		}

		pLdrData = (PPEB_LDR_DATA)(PDWORD)(*(PDWORD)(dwPEB + 12));
		#else
		BYTE* _teb = (BYTE*)__readgsqword(0x30);
		pLdrData = (PPEB_LDR_DATA)(PULONGLONG)(*(PULONGLONG)((*(PULONGLONG)(_teb + 0x60)) + 0x18));
		#endif  

		for (; i < 3; i++)
		{
			switch (i)
			{
			case 0:
				pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InLoadOrderModuleList));
				dwOffset = 0;
				break;

			case 1:
				pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InMemoryOrderModuleList));
				#ifndef _WIN64
				dwOffset = 8;
				#else
				dwOffset = 16;
				#endif
				break;
			case 2:
				pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InInitializationOrderModuleList));
				#ifndef _WIN64
				dwOffset = 16;
				#else
				dwOffset = 32;
				#endif
				break;
			}

			while (pUserModule->Flink != pUserModuleHead)
			{
				pUserModule = pUserModule->Flink;
				#ifndef _WIN64
				lpModule = (PUNICODE_STRING)(((DWORD)(pUserModule)) + (36 - dwOffset));
				#else
				lpModule = (PUNICODE_STRING)(((LONGLONG)(pUserModule)) + (72 - dwOffset));
				#endif          

				for (n = 0; n < (lpModule->Length) / 2 && n < 512; n++)
					szModuleName[n] = (CHAR)(*((lpModule->Buffer) + (n)));

				szModuleName[n] = '\0';
				if (strstr(szModuleName, szModuleStr))
				{
					printf("\t[i]: Module %s \n", szModuleName);
					#ifndef _WIN64
					if (!pLdrModule)
						pLdrModule = (PLDR_MODULE)(((DWORD)(pUserModule)) - dwOffset);
					#else
					if (!pLdrModule)
						pLdrModule = (PLDR_MODULE)(((LONGLONG)(pUserModule)) - dwOffset);
					#endif              
					pUserModule->Blink->Flink = pUserModule->Flink;
					pUserModule->Flink->Blink = pUserModule->Blink;
				}
			}
		}

		if (pLdrModule)
		{
			pLdrModule->HashTableEntry.Blink->Flink = pLdrModule->HashTableEntry.Flink;
			pLdrModule->HashTableEntry.Flink->Blink = pLdrModule->HashTableEntry.Blink;
		}
	}

	void StompPEHeaders(HANDLE hProcess) {

		//PE DOS HEADER
		LPCSTR _pattern = "\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x54\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20\x6d\x6f\x64\x65";

		printf("[+]: Obtaining a handle of the current process: %d\n", (INT_PTR)hProcess);
		fflush(stdout);

		size_t _len;

		printf("[+]: Scanning for PE DOS Header 'MZ...' pattern...\n");
		fflush(stdout);
		LPSTR* PE_Header_Addresses = FindPattern(hProcess, _pattern, &_len);

		printf("[i]: %d PE DOS Headers found.\n", (INT_PTR)_len);
		printf("[+]: Stomping %d PE DOS headers:\n", (INT_PTR)_len);
		fflush(stdout);

		for (size_t i = 0; i < _len; i++) {
			printf("\t[i]: Stomping MZ Header: 0x%x\n", (unsigned int)*(PE_Header_Addresses + i));
			StompPEDOSHeader(*(PE_Header_Addresses + i));
			fflush(stdout);
		}

		free(PE_Header_Addresses);
		NtClose(hProcess);

	}

	void StompPEDOSHeader(LPSTR ntheaderAddr)
	{

		LPSTR olNtH = ntheaderAddr;
		LPVOID nthAddr = (LPVOID)ntheaderAddr;
		NTSTATUS status;
		SIZE_T page = 4096;
		DWORD Protect;

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ntheaderAddr;

		if (pDosHeader->e_magic != 0x5a4d) {
			printf("\t\t[-]: Not a valid PE DOS Header\n");
			fflush(stdout);
			return;
		}

		//zeroing out 224 bytes of the PE Header leads to crashing the loaded .net assembly, I'm only patching specific PE DOS HEADER signatured offsets and byte sequences as a workaround.
		SIZE_T Size = 2;

		status = NtProtectVirtualMemory(NtGetCurrentProcess(), &nthAddr, &page, PAGE_READWRITE, &Protect);
		if (!NT_SUCCESS(status)) {
			//printf("\t\t[!]: Error NtProtectVirtualMemory\n");
			return;
		}

		RtlZeroMemory((PVOID)olNtH, Size);
		RtlZeroMemory((PVOID)(olNtH + Size + 75), Size + 37);

		status = NtProtectVirtualMemory(NtGetCurrentProcess(), &nthAddr, &page, Protect, &Protect);
		if (!NT_SUCCESS(status)) {
			//printf("\t\t[!]: Error NtProtectVirtualMemory (restore permissions)\n");
			return;
		}



	}
}