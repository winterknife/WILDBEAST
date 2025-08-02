#include <Windows.h>
#include "Load.h"
#include "Resource.h"

extern "C" __attribute__((noreturn)) VOID __stdcall ExeEntry(
	VOID
) {
	DWORD dwSize = 0;
	PVOID pData = NULL;
	HANDLE hStdOutput = NULL;

	extract_payload(GetModuleHandle(NULL), IDR_PAYLOAD, RCDATA, &dwSize, &pData);

	AllocConsole();

	hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	WriteConsoleA(hStdOutput, pData, (DWORD)strlen((PCSTR)pData), NULL, NULL);

	MessageBoxA(NULL, (PCSTR)pData, "TEST!", MB_OK);

	FreeConsole();

	ExitProcess(0);
}