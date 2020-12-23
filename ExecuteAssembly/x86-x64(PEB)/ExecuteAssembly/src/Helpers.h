#ifndef _HELPERS_H
#define _HELPERS_H

#include <metahost.h>
#include <stdint.h>

extern const char b64chars[];
extern int b64invs[];

extern ULONG b64DecodeSize(LPCSTR in);
extern void b64GenDecodeTable();
extern int isValidb64Char(uint8_t c);
extern int b64Decode(LPCSTR in, LPSTR out, size_t outlen);
extern bool checkCLRVersion(LPCSTR assmblyBytes, size_t assemblyLength, LPCSTR byteSeq, size_t byteSeqLength);
extern LPSTR xorDecrypt(LPSTR data, uint8_t key, size_t _binLength);
extern LPSTR trim(LPSTR str);
extern LPSTR strmbtok(LPSTR input, LPSTR delimit, LPSTR openblock, LPSTR closeblock);
extern void removeChar(LPSTR str, const uint8_t toRemove);

#endif 
