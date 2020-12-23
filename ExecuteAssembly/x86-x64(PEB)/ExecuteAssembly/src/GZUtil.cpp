#include "GZUtil.h"

int decompress(LPSTR dst, ULONG *dst_length, LPSTR src, ULONG src_length)
{
	z_stream stream;
	memset(&stream, 0, sizeof(stream));

	stream.next_in = (Bytef*)src;
	stream.avail_in = src_length;

	stream.next_out = (Bytef*)dst;
	stream.avail_out = *dst_length;

	int rv = inflateInit2(&stream, 15 + 16);
	if (Z_OK == rv) {
		rv = inflate(&stream, Z_NO_FLUSH);
		if (Z_STREAM_END == rv) {
			inflateEnd(&stream);
			rv = Z_OK;
		}
	}

	if (Z_OK == rv) {
		*dst_length = stream.total_out;
	}
	else {
		*dst_length = 0;
	}

	return rv;
}
