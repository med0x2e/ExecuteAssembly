#ifndef _UNLINK_MODULE_H
#define _UNLINK_MODULE_H

#include <stdio.h>
#include <Windows.h>

namespace PEModuleHelper {
	extern void UnlinkModuleWithStr(LPSTR szModuleStr);
	extern void StompPEHeaders(HANDLE hProcess);
	extern void StompPEDOSHeader(LPSTR ntHeaderAddr);
}

using namespace PEModuleHelper;

#define _separator() printf("[*]:-----------------------------------------\n")

#endif