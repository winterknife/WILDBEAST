#include <Windows.h>
#include <stdio.h>
#include "Load.h"
#include "Resource.h"

extern "C" __attribute__((noinline)) void __stdcall log_console(_Printf_format_string_ PCSTR strFormat, ...) {
    // Init local variables
    va_list pchArgs;

    // Printf message
    va_start(pchArgs, strFormat);
    vprintf_s(strFormat, pchArgs);
    va_end(pchArgs);
}

extern "C" __attribute__((noreturn)) VOID __stdcall ExeEntry(
	VOID
) {
	DWORD dwSize = 0;
	PVOID pData = NULL;

	extract_payload(GetModuleHandle(NULL), IDR_PAYLOAD, RCDATA, &dwSize, &pData);

	AllocConsole();

	AttachConsole(ATTACH_PARENT_PROCESS);

	freopen("CONOUT$", "wb", stdout);

	log_console("%s\n", pData);

	MessageBoxA(NULL, (PCSTR)pData, "TEST!", MB_OK);

	FreeConsole();

	ExitProcess(0);
}