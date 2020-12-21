#ifndef _HOST_CLR_H
#define _HOST_CLR_H

#include <metahost.h>
#include <stdio.h>


#pragma comment(lib, "MSCorEE.lib")

#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")

using namespace mscorlib;
extern int InjectAssembly(LPSTR assemblyBytes, ULONG assemblyLength, LPSTR* args, size_t argsCount, const wchar_t* _unlinkmodules, const wchar_t* _stompheaders, const wchar_t* _amsi, const wchar_t* _etw);
extern BOOL isCLRLoaded(LPWSTR version, IEnumUnknown* pEnumerator, LPVOID* pRuntimeInfo);
extern BOOL _CLRCreateInstance(ICLRMetaHost** pMetaHost);
extern BOOL _GetRuntime(ICLRMetaHost* pMetaHost, ICLRRuntimeInfo** pRuntimeInfo, LPWSTR _version);
extern BOOL _isLoadable(ICLRRuntimeInfo* pRuntimeInfo);
extern BOOL _GetInterface(ICorRuntimeHost** pRuntimeHost, ICLRRuntimeInfo* pRuntimeInfo);
extern BOOL _StartRuntimeHost(ICorRuntimeHost* pRuntimeHost);
extern BOOL isCLRLoaded(LPWSTR version, IEnumUnknown* pEnumerator, LPVOID* pRuntimeInfo);
extern BOOL _GetDefaultDomain(ICorRuntimeHost* pRuntimeHost, IUnknown** pAppDomainThunk);
extern BOOL _QueryInterface(_AppDomain** pDefaultAppDomain, IUnknown* pAppDomainThunk);
extern BOOL _SafeArrayAccessData(SAFEARRAY** pSafeArray, PVOID* pvData);
extern BOOL _SafeArrayUnaccessData(SAFEARRAY* pSafeArray);
extern BOOL _Load(_AppDomain* pDefaultAppDomain, SAFEARRAY* pSafeArray, _Assembly** pAssembly);
extern BOOL _GetEntryPoint(_Assembly* pAssembly, _MethodInfo** pMethodInfo);
extern SAFEARRAY* setEntrypointParams(LPSTR* arguments, size_t argsCount);
extern void unlinkModules();
extern void cleanup(SAFEARRAY* params, ICorRuntimeHost* pRuntimeHost, ICLRRuntimeInfo* pRuntimeInfo, ICLRMetaHost* pMetaHost, IEnumUnknown* pRuntimeEnum);


#define ARRLEN(arr) (sizeof(arr)/sizeof((arr)[0]))
#define _separator() printf("[*]:-----------------------------------------\n")



#endif
