#ifndef _PEB_H
#define _PEB_H

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define ADDR unsigned __int64
#define RESOLVE_NAME_MAX 4096
#define NtGetCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

enum ModuleHash {
	_kernel32dll = 0x4315072E,
	_ntdlldll = 0xDDB0C76F,
	_amsidll = 0xF076AE24
};

enum APIHash {
	_AmsiScanBuffer = 0xCC03EE21,
	_EtwEventWriteFull = 0x701D3D4F,
	_EtwEventWrite = 0x50710627
};

typedef enum AMSI_RESULT {
	AMSI_RESULT_CLEAN,
	AMSI_RESULT_NOT_DETECTED,
	AMSI_RESULT_BLOCKED_BY_ADMIN_START,
	AMSI_RESULT_BLOCKED_BY_ADMIN_END,
	AMSI_RESULT_DETECTED
} AMSI_RESULT, PAMSI_RESULT;


extern HRESULT UToAnsi(LPCOLESTR pszW, LPSTR* ppszA);
extern ADDR findExportAddr(ADDR moduleBase, UINT32 exportHash);
extern ADDR findModuleBase(UINT32 moduleHash);
extern UINT32 resolve(LPCSTR cszName);

typedef HRESULT(WINAPI* _PFNAmsiScanBuffer)(HRESULT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HRESULT amsiSession, AMSI_RESULT result);


extern DWORD NtGetCurrentProcessId(HANDLE hProcess);

#endif