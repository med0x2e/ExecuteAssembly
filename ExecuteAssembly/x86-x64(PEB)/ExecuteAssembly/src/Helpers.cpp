#include "Helpers.h"

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };

ULONG b64DecodeSize(LPCSTR in) {
	ULONG len;
	ULONG ret;
	ULONG i;

	if (in == NULL)
		return 0;

	len = strlen(in);
	ret = len / 4 * 3;

	for (i = len; i-- > 0; ) {
		if (in[i] == '=') {
			ret--;
		}
		else {
			break;
		}
	}

	return ret;
}

void b64GenDecodeTable() {
	size_t    inv[80];
	size_t i;

	memset(inv, -1, sizeof(inv));
	for (i = 0; i < sizeof(b64chars) - 1; i++) {
		inv[b64chars[i] - 43] = i;
	}
}

int isValidb64Char(uint8_t c) {
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c == '+' || c == '/' || c == '=')
		return 1;
	return 0;
}

int b64Decode(LPCSTR in, LPSTR bytes, size_t bytesLen) {
	size_t len;
	size_t i;
	size_t j;
	int    v;

	if (in == NULL || bytes == NULL)
		return 0;

	len = strlen(in);
	if (bytesLen < b64DecodeSize(in) || len % 4 != 0)
		return 0;

	for (i = 0; i < len; i++) {
		if (!isValidb64Char(in[i])) {
			return 0;
		}
	}

	for (i = 0, j = 0; i < len; i += 4, j += 3) {
		v = b64invs[in[i] - 43];
		v = (v << 6) | b64invs[in[i + 1] - 43];
		v = in[i + 2] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 2] - 43];
		v = in[i + 3] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 3] - 43];

		bytes[j] = (v >> 16) & 0xFF;
		if (in[i + 2] != '=')
			bytes[j + 1] = (v >> 8) & 0xFF;
		if (in[i + 3] != '=')
			bytes[j + 2] = v & 0xFF;
	}

	return 1;
}

LPSTR trim(LPSTR str) {
	char *end;
	while (isspace((unsigned char)*str)) str++;

	if (*str == 0)
		return str;

	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end)) end--;

	end[1] = '\0';

	return str;
}

bool checkCLRVersion(LPCSTR assmblyBytes, size_t assemblyLength, LPCSTR byteSeq, size_t byteSeqLength) {
	for (size_t _index = 0; _index < assemblyLength; _index++) {
		if (byteSeq[0] == assmblyBytes[_index] && byteSeq[9] == assmblyBytes[_index + 9]
			&& byteSeq[2] == assmblyBytes[_index + 2] && byteSeq[6] == assmblyBytes[_index + 6]) {
			return true;
		}
	}

	return false;
}

LPSTR xorDecrypt(LPSTR data, uint8_t key, size_t _binLength) {
	for (int _i = 0; _i < _binLength; _i++) {
		data[_i] = data[_i] ^ key;
	}
	return data;
}

LPSTR toLower(LPSTR strVar)
{
	char* pstr = strVar;
	while (*pstr++)
		*pstr = (char)tolower(*pstr);

	return pstr;
}

//stackoverflow.com/questions/26187037/in-c-split-char-on-spaces-with-strtok-function-except-if-between-quotes
LPSTR strmbtok(LPSTR input, LPSTR delimit, LPSTR openblock, LPSTR closeblock) {
	static char *token = NULL;
	char *lead = NULL;
	char *block = NULL;
	int iBlock = 0;
	int iBlockIndex = 0;

	if (input != NULL) {
		token = input;
		lead = input;
	}
	else {
		lead = token;
		if (*token == '\0') {
			lead = NULL;
		}
	}

	while (*token != '\0') {
		if (iBlock) {
			if (closeblock[iBlockIndex] == *token) {
				iBlock = 0;
			}
			token++;
			continue;
		}
		if ((block = strchr(openblock, *token)) != NULL) {
			iBlock = 1;
			iBlockIndex = block - openblock;
			token++;
			continue;
		}
		if (strchr(delimit, *token) != NULL) {
			*token = '\0';
			token++;
			break;
		}
		token++;
	}
	return lead;
}

void removeChar(LPSTR str, uint8_t toRemove) {

	char *src, *dst;
	for (src = dst = str; *src != '\0'; src++) {
		*dst = *src;
		if (*dst != toRemove) dst++;
	}
	*dst = '\0';
}

LPSTR _strtok(LPSTR data, const LPSTR delim, LPSTR pNext, size_t dLen)
{
	static LPSTR sTok = (char*)malloc(dLen);
	register LPSTR cpy = (char*)pNext;
	memset(sTok, 0, sizeof(sTok));

	if (data != NULL)
		strcpy(cpy, data);

	if (cpy == NULL)
		return NULL;

	int i = 0;

	for (i = 0; i < dLen; i++)
	{
		if (cpy[i] == delim[0]) break;
		if (cpy[i] == delim[1])
		{
			cpy = NULL;
			break;
		}
		sTok[i] = cpy[i];
	}

	if (cpy != NULL) strcpy(cpy, &cpy[i + 1]);

	return sTok;
}