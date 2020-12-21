#include "PEB.h"

DWORD NtGetCurrentProcessId(HANDLE hProcess) {

	ULONG_PTR _pid = NULL;
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	NTSTATUS status;
	PULONG RqSize = 0;

	status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), RqSize);
	if (!NT_SUCCESS(status)) {
		printf("[!]: Errror NtQueryInformationProcess\n");
		fflush(stdout);
		return NULL;
	}

	_pid = pbi.UniqueProcessId;

	return _pid;
}

HRESULT UToAnsi(LPCOLESTR pszW, LPSTR* ppszA) {
	ULONG_PTR cbAnsi, cCharacters;
	DWORD dwError;

	if (pszW == NULL){
		*ppszA = NULL;
		return NOERROR;
	}
	cCharacters = wcslen(pszW) + 1;
	cbAnsi = cCharacters * 2;

	*ppszA = (LPSTR)CoTaskMemAlloc(cbAnsi);
	if (NULL == *ppszA)
		return E_OUTOFMEMORY;

	if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA, cbAnsi, NULL, NULL))
	{
		dwError = GetLastError();
		CoTaskMemFree(*ppszA);
		*ppszA = NULL;
		return HRESULT_FROM_WIN32(dwError);
	}
	return NOERROR;
}

ADDR findExportAddr(ADDR moduleBase, UINT32 exportHash) {
	PIMAGE_DOS_HEADER peHeader = (PIMAGE_DOS_HEADER)moduleBase;
	PIMAGE_NT_HEADERS peNtHeaders = (PIMAGE_NT_HEADERS)(moduleBase + peHeader->e_lfanew);

	DWORD exportDescriptorOffset = peNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + exportDescriptorOffset);

	DWORD* name_table = (DWORD*)(moduleBase + exportTable->AddressOfNames);
	WORD* ordinal_table = (WORD*)(moduleBase + exportTable->AddressOfNameOrdinals);
	DWORD* func_table = (DWORD*)(moduleBase + exportTable->AddressOfFunctions);

	for (DWORD i = 0; i < exportTable->NumberOfNames; ++i) {
		char* funcName = (char*)(moduleBase + name_table[i]);
		ADDR func_ptr = moduleBase + func_table[ordinal_table[i]];
		if (resolve(funcName) == exportHash) {
			return func_ptr;
		}
	}

	return NULL;
}

ADDR findModuleBase(UINT32 moduleHash) {

	PTEB teb;

	#if defined(_WIN64)
		teb = (PTEB)__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self));
	#else
		teb = (PTEB)__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self));
	#endif

	PPEB_LDR_DATA loader = teb->ProcessEnvironmentBlock->Ldr;

	PLIST_ENTRY head = &loader->InMemoryOrderModuleList;
	PLIST_ENTRY curr = head->Flink;

	do {
		PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		char* dllName;
	
		UToAnsi(dllEntry->FullDllName.Buffer, &dllName);
		strlwr(dllName);

		CoTaskMemFree(dllName);
		
		char* dllFileName;
		(dllFileName = strrchr(dllName, '\\')) ? ++dllFileName : (dllFileName = dllName);
		UINT32 dllNameHash = resolve(dllFileName);
		if (moduleHash == dllNameHash) {
			return (ADDR)dllEntry->DllBase;
		}
		curr = curr->Flink;
	} while (curr != head);

	return NULL;
}

UINT32 resolve(LPCSTR cszName)
{
	if (cszName == NULL){
		return 0;
	}

	SIZE_T uNameLen = strnlen_s(cszName, RESOLVE_NAME_MAX);
	if (uNameLen == 0){
		return 0;
	}

	UINT32 u32Hash = 0, u32Buf = 0;
	PBYTE pbData = (PBYTE)cszName;
	INT iRemain = (uNameLen & 3);

	uNameLen >>= 2;

	for (SIZE_T i = uNameLen; i > 0; i--){
		u32Hash += *(const UINT16*)pbData;
		u32Buf = (*(const UINT16*)(pbData + 2) << 11) ^ u32Hash;
		u32Hash = (u32Hash << 16) ^ u32Buf;
		pbData += (2 * sizeof(UINT16));
		u32Hash += u32Hash >> 11;
	}

	switch (iRemain)
	{
	case 1:
		u32Hash += *pbData;
		u32Hash ^= u32Hash << 10;
		u32Hash += u32Hash >> 1;
		break;

	case 2:
		u32Hash += *(const UINT16*)pbData;
		u32Hash ^= u32Hash << 11;
		u32Hash += u32Hash >> 17;
		break;

	case 3:
		u32Hash += *(const UINT16*)pbData;
		u32Hash ^= u32Hash << 16;
		u32Hash ^= pbData[sizeof(UINT16)] << 18;
		u32Hash += u32Hash >> 11;
		break;
	}

	u32Hash ^= u32Hash << 3;
	u32Hash += u32Hash >> 5;
	u32Hash ^= u32Hash << 4;
	u32Hash += u32Hash >> 17;
	u32Hash ^= u32Hash << 25;
	u32Hash += u32Hash >> 6;

	return u32Hash;
}