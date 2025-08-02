#include "Load.h"

VOID __stdcall extract_payload(
	HMODULE hModule,
	DWORD   dwResourceName,
	DWORD   dwResourceType,
	PDWORD  pdwSize,
	PVOID*  ppData
) {
    HRSRC hResource = FindResourceW(hModule, MAKEINTRESOURCEW(dwResourceName), MAKEINTRESOURCEW(dwResourceType));

    HGLOBAL hResourceData = LoadResource(hModule, hResource);

    *pdwSize = SizeofResource(hModule, hResource);

    *ppData = LockResource(hResourceData);
}