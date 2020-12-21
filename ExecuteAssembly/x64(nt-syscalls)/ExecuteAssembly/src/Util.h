#ifndef _UTIL_H
#define _UTIL_H

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <evntprov.h>

typedef ULONG(NTAPI *_PFNEtwEventWriteFull)(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in USHORT EventProperty,
	__in_opt LPCGUID ActivityId,
	__in_opt LPCGUID RelatedActivityId,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	);


extern void patchAmci();

extern void patchEtw();

#define _separator() printf("[*]:-----------------------------------------\n")

#endif