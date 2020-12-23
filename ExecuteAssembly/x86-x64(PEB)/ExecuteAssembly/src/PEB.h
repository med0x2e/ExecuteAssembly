#ifndef _PEB_H
#define _PEB_H

#include <windows.h>
#include <winternl.h>
#include <stdio.h>


#define ADDR unsigned __int64
#define RESOLVE_NAME_MAX 4096

enum ModuleHash {
	_kernel32dll = 0x4315072E,
	_ntdlldll = 0xDDB0C76F,
	_amsidll = 0xF076AE24
};

enum APIHash {
	_GetCurrentProcess = 0x7DEB3C2B,
	_GetCurrentProcessId = 0x9E6C4C,
	_VirtualProtect = 0xF64C586A,
	_ReadProcessMemory = 0x74E872CE,
	_OpenProcess = 0xF5C7CDFE,
	_VirtualQueryEx = 0xFEB1E211,
	_AmsiScanBuffer = 0xCC03EE21,
	_VirtualProtectEx = 0xC43C8F09,
	_WriteProcessMemory = 0x3FBA5504,
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

typedef HANDLE(WINAPI* _PFNGetCurrentProcess)();

typedef DWORD(WINAPI* _PFNGetCurrentProcessId)();

typedef BOOL(WINAPI* _PFNVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);

typedef BOOL(WINAPI* _PFNReadProcessMemory)(HANDLE  hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);

typedef HANDLE(WINAPI* _PFNOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

typedef SIZE_T(WINAPI* _PFNVirtualQueryEx)(HANDLE  hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);

typedef HRESULT(WINAPI* _PFNAmsiScanBuffer)(HRESULT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HRESULT amsiSession, AMSI_RESULT result);

typedef BOOL(WINAPI* _PFNVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);

typedef BOOL(WINAPI* _PFNWriteProcessMemory)(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten);



#endif