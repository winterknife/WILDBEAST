#pragma once

#include <Windows.h>

extern "C" VOID __stdcall extract_payload(
	HMODULE hModule,
	DWORD   dwResourceName,
	DWORD   dwResourceType,
	PDWORD  pdwSize,
	PVOID*  ppData
);