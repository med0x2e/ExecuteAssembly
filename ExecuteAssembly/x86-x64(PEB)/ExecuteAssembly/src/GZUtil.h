#ifndef _GZUTIL_H
#define _GZUTIL_H

#include "windows.h" 

#define Byte zlib_Byte
#include "zlib.h"
#undef Byte

extern int decompress(LPSTR dst, ULONG *dst_length, LPSTR src, ULONG src_length);

#endif