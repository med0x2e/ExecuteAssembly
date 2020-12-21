#ifndef _RDI_RDI_H
#define _RDI_RDI_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>


#define DLL_QUERY_HMODULE		6

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR (WINAPI * REFLECTIVELOADER)( VOID );
typedef BOOL (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );

#define DLLEXPORT   __declspec( dllexport ) 


#endif

