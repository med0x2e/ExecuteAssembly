#pragma once

#ifndef _PATTERN_SCAN_H
#define _PATTERN_SCAN_H

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>

using namespace std;

extern LPSTR* FindPattern(HANDLE process, LPCSTR pattern, size_t* _len);
template <class AIterator, class BIterator>
extern void Check(LPSTR base, AIterator buf_start, AIterator buf_end, BIterator pat_start, BIterator pat_end, LPSTR* PE_Header_Addresses, size_t* _len);

#define NUMBER_OF_ADDRS 30

#endif