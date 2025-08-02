#include <Windows.h>
#include "Load.h"
#include "Resource.h"

extern "C" __declspec(dllexport) VOID __stdcall execute_payload(
	HWND    hwnd,
	HMODULE hModule,
	PCSTR   strCmdLine,
	DWORD   dwCmdShow
) {
	UNREFERENCED_PARAMETER(hwnd);
	UNREFERENCED_PARAMETER(hModule);
	UNREFERENCED_PARAMETER(dwCmdShow);

	if (strlen(strCmdLine) != 0)
		MessageBoxA(NULL, strCmdLine, "TEST!", MB_OK);
}

extern "C" BOOLEAN __stdcall DllEntry(
	HMODULE hModule,
    DWORD   dwReason,
    PVOID   pReserved
) {
	UNREFERENCED_PARAMETER(pReserved);

	DWORD dwSize = 0;
	PVOID pData = NULL;

    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
			MessageBoxA(NULL, "DLL_PROCESS_ATTACH!", "TEST!", MB_OK);
			DisableThreadLibraryCalls(hModule);
			extract_payload(hModule, IDR_PAYLOAD, RCDATA, &dwSize, &pData);
			execute_payload(NULL, NULL, (PCSTR)pData, 0);
            break;

        case DLL_PROCESS_DETACH:
			MessageBoxA(NULL, "DLL_PROCESS_DETACH!", "TEST!", MB_OK);
            break;
    }

    return TRUE;
}