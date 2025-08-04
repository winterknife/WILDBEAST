/*
 * Copyright (C) 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
 *
 * This file is part of Tradecraft Garden
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
 * This file is derived from The Tradecraft Garden project by Raphael Mudge.
 * A few items were removed, but otherwise, this should largely be unchanged.
 *
 * https://tradecraftgarden.org/tradecraft.html
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <intrin.h>

#define WIN_X64

#define WIN32_FUNC(x) __typeof__( x ) * x

#define PTR_OFFSET(x, y) (void*)((ULONG_PTR)(x) + (ULONG)(y))

#define HASH_KEY 13
#define KERNEL32DLL_HASH    0x6A4ABC5B
#define LOADLIBRARYA_HASH   0xEC0E4E8E
#define GETPROCADDRESS_HASH 0x7C0DFCAA

typedef struct _UNICODE_STR {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpadded"
typedef struct _LDR_DATA_TABLE_ENTRY {
	//LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#pragma GCC diagnostic pop

typedef struct _PEB_LDR_DATA {
   DWORD dwLength;
   DWORD dwInitialized;
   LPVOID lpSsHandle;
   LIST_ENTRY InLoadOrderModuleList;
   LIST_ENTRY InMemoryOrderModuleList;
   LIST_ENTRY InInitializationOrderModuleList;
   LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpadded"
typedef struct _PEB_FREE_BLOCK {
   struct _PEB_FREE_BLOCK* pNext;
   DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpadded"
typedef struct __PEB {
   BYTE bInheritedAddressSpace;
   BYTE bReadImageFileExecOptions;
   BYTE bBeingDebugged;
   BYTE bSpareBool;
   LPVOID lpMutant;
   LPVOID lpImageBaseAddress;
   PPEB_LDR_DATA pLdr;
   LPVOID lpProcessParameters;
   LPVOID lpSubSystemData;
   LPVOID lpProcessHeap;
   PRTL_CRITICAL_SECTION pFastPebLock;
   LPVOID lpFastPebLockRoutine;
   LPVOID lpFastPebUnlockRoutine;
   DWORD dwEnvironmentUpdateCount;
   LPVOID lpKernelCallbackTable;
   DWORD dwSystemReserved;
   DWORD dwAtlThunkSListPtr32;
   PPEB_FREE_BLOCK pFreeList;
   DWORD dwTlsExpansionCounter;
   LPVOID lpTlsBitmap;
   DWORD dwTlsBitmapBits[2];
   LPVOID lpReadOnlySharedMemoryBase;
   LPVOID lpReadOnlySharedMemoryHeap;
   LPVOID lpReadOnlyStaticServerData;
   LPVOID lpAnsiCodePageData;
   LPVOID lpOemCodePageData;
   LPVOID lpUnicodeCaseTableData;
   DWORD dwNumberOfProcessors;
   DWORD dwNtGlobalFlag;
   LARGE_INTEGER liCriticalSectionTimeout;
   DWORD dwHeapSegmentReserve;
   DWORD dwHeapSegmentCommit;
   DWORD dwHeapDeCommitTotalFreeThreshold;
   DWORD dwHeapDeCommitFreeBlockThreshold;
   DWORD dwNumberOfHeaps;
   DWORD dwMaximumNumberOfHeaps;
   LPVOID lpProcessHeaps;
   LPVOID lpGdiSharedHandleTable;
   LPVOID lpProcessStarterHelper;
   DWORD dwGdiDCAttributeList;
   LPVOID lpLoaderLock;
   DWORD dwOSMajorVersion;
   DWORD dwOSMinorVersion;
   WORD wOSBuildNumber;
   WORD wOSCSDVersion;
   DWORD dwOSPlatformId;
   DWORD dwImageSubsystem;
   DWORD dwImageSubsystemMajorVersion;
   DWORD dwImageSubsystemMinorVersion;
   DWORD dwImageProcessAffinityMask;
   DWORD dwGdiHandleBuffer[34];
   LPVOID lpPostProcessInitRoutine;
   LPVOID lpTlsExpansionBitmap;
   DWORD dwTlsExpansionBitmapBits[32];
   DWORD dwSessionId;
   ULARGE_INTEGER liAppCompatFlags;
   ULARGE_INTEGER liAppCompatFlagsUser;
   LPVOID lppShimData;
   LPVOID lpAppCompatInfo;
   UNICODE_STR usCSDVersion;
   LPVOID lpActivationContextData;
   LPVOID lpProcessAssemblyStorageMap;
   LPVOID lpSystemDefaultActivationContextData;
   LPVOID lpSystemAssemblyStorageMap;
   DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;
#pragma GCC diagnostic pop

typedef struct {
	IMAGE_DOS_HEADER      * DosHeader;
	IMAGE_NT_HEADERS      * NtHeaders;
	IMAGE_OPTIONAL_HEADER * OptionalHeader;
} DLLDATA;

typedef struct {
    WIN32_FUNC(LoadLibraryA);
    WIN32_FUNC(GetProcAddress);
} WIN32FUNCS;

typedef int __cdecl (*vsnprintf_t)(char * d, size_t n, char * format, ...);

typedef struct {
	WIN32_FUNC(VirtualAlloc);
	WIN32_FUNC(VirtualFree);
	WIN32_FUNC(OutputDebugStringA);
	vsnprintf_t vsnprintf;
} DPRINTFFUNCS;

extern "C" VOID __stdcall wus_poppin(
	VOID
);

extern "C" VOID __stdcall PicEntry(
	VOID
) {
	wus_poppin();
}

__forceinline DWORD ror(DWORD d) {
	return _rotr(d, HASH_KEY);
}

__forceinline DWORD hash(char* c) {
    DWORD h = 0;
	do {
		h = ror(h);
        h += *c;
	} while(*++c);

    return h;
}

extern "C" char* findModuleByHash(DWORD moduleHash) {
	_PEB                 * pPEB;
	LDR_DATA_TABLE_ENTRY * pEntry;
	char                 * name;
	DWORD                  hashValue;
	USHORT                 counter;

#if defined WIN_X64
	pPEB = (_PEB*)__readgsqword(0x60);
#elif defined WIN_X86
	pPEB = (_PEB*)__readfsdword(0x30);
#else
#error "Neither WIN_X64 or WIN_X86 is defined"
#endif

	pEntry = (LDR_DATA_TABLE_ENTRY*)pPEB->pLdr->InMemoryOrderModuleList.Flink;

	while (pEntry) {
		name      = (char *)pEntry->BaseDllName.pBuffer;
		counter   = pEntry->BaseDllName.Length;

		hashValue = 0;
		do {
			hashValue = ror(hashValue);
			if (*name >= 'a')
				hashValue += (BYTE)*name - 0x20;
			else
				hashValue += (BYTE)*name;

			name++;
		} while (--counter);

		if (hashValue == moduleHash)
			return (char*)pEntry->DllBase;

		pEntry = (LDR_DATA_TABLE_ENTRY*)pEntry->InMemoryOrderModuleList.Flink;
	}

	return NULL;
}

extern "C" void ParseDLL(char* src, DLLDATA* data) {
	data->DosHeader      = (IMAGE_DOS_HEADER *)src;
	data->NtHeaders      = (IMAGE_NT_HEADERS *)(src + data->DosHeader->e_lfanew);
	data->OptionalHeader = (IMAGE_OPTIONAL_HEADER *)&(data->NtHeaders->OptionalHeader);
}

extern "C" IMAGE_DATA_DIRECTORY* GetDataDirectory(DLLDATA* dll, UINT entry) {
	return dll->OptionalHeader->DataDirectory + entry;
}

extern "C" void* findFunctionByHash(char * src, DWORD wantedFunction) {
	DLLDATA                  data;
	IMAGE_DATA_DIRECTORY   * exportTableHdr;
	IMAGE_EXPORT_DIRECTORY * exportDir;
	DWORD                  * exportName;
	WORD                   * exportOrdinal;
	DWORD                  * exportAddress;
	DWORD                    hashValue;

	ParseDLL(src, &data);

	exportTableHdr = GetDataDirectory(&data, IMAGE_DIRECTORY_ENTRY_EXPORT);
	exportDir      = (IMAGE_EXPORT_DIRECTORY*)PTR_OFFSET(src, exportTableHdr->VirtualAddress);

	exportName    = (DWORD*)PTR_OFFSET(src, exportDir->AddressOfNames);
	exportOrdinal = (WORD*) PTR_OFFSET(src, exportDir->AddressOfNameOrdinals);

	while (TRUE) {
		hashValue = hash((char*)PTR_OFFSET(src, *exportName));
		if (hashValue == wantedFunction) {
			exportAddress   = (PDWORD)PTR_OFFSET(src, exportDir->AddressOfFunctions);

			exportAddress  += *exportOrdinal;

			return PTR_OFFSET(src, *exportAddress);
		}

		exportName++;
		exportOrdinal++;
	}
}

extern "C" void findNeededFunctions(WIN32FUNCS* funcs) {
    char* hModule = (char*)findModuleByHash(KERNEL32DLL_HASH);

    funcs->LoadLibraryA   = (__typeof__(LoadLibraryA)*)   findFunctionByHash(hModule, LOADLIBRARYA_HASH);
    funcs->GetProcAddress = (__typeof__(GetProcAddress)*) findFunctionByHash(hModule, GETPROCADDRESS_HASH);
}

extern "C" void __dprintf(DPRINTFFUNCS* funcs, char* format, va_list* args) {
	int    len;
	char * temp;

	len  = funcs->vsnprintf(NULL, 0, format, *args);

	temp = (char*)funcs->VirtualAlloc(NULL, len + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (temp == NULL) {
		return;
	}
	//__stosb((unsigned char *)temp, 0, len + 1);

	funcs->vsnprintf(temp, len + 1, format, *args);

	funcs->OutputDebugStringA(temp);

	funcs->VirtualFree(temp, 0, MEM_RELEASE);
}

extern "C" void dprintf(WIN32FUNCS* ifuncs, char* format, ...) {
	va_list args;
	HMODULE mod;

	DPRINTFFUNCS funcs;

	char kern32[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', 0 };
	char vastr[]  = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
	char vfstr[]  = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0 };
	char odstr[]  = { 'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'A', 0 };

	char msvcrt[] = { 'M', 'S', 'V', 'C', 'R', 'T', 0 };
	char pfstr[]  = { 'v', 's', 'n', 'p', 'r', 'i', 'n', 't', 'f', 0 };

	mod                      = ifuncs->LoadLibraryA(kern32);
	funcs.VirtualAlloc       = (__typeof__(VirtualAlloc)*)((PVOID)ifuncs->GetProcAddress(mod, vastr));
	funcs.VirtualFree        = (__typeof__(VirtualFree)*)((PVOID)ifuncs->GetProcAddress(mod, vfstr));
	funcs.OutputDebugStringA = (__typeof__(OutputDebugStringA)*)((PVOID)ifuncs->GetProcAddress(mod, odstr));

	mod                      = ifuncs->LoadLibraryA(msvcrt);
	funcs.vsnprintf          = (vsnprintf_t)((PVOID)ifuncs->GetProcAddress(mod, pfstr));

	va_start(args, format);
	__dprintf(&funcs, format, &args);
	va_end(args);
}

VOID __stdcall wus_poppin(
	VOID
) {
	WIN32FUNCS funcs;
	findNeededFunctions(&funcs);

	WIN32_FUNC(MessageBoxA);

	char strUser32[] = { 'U', 's', 'e', 'r', '3', '2', 0 };
	char strMessageBoxA[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };
	char strHelloWorld[] = { 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', ' ', 'f', 'r', 'o', 'm', ' ', 'P', 'I', 'C', '!', 0 };
	char strTest[] = { 'T', 'E', 'S', 'T', '!', 0 };

	char strDebug[] = { '%', 'p', 0 };

	HMODULE hUser32 = funcs.LoadLibraryA(strUser32);
	MessageBoxA = (decltype(MessageBoxA))((PVOID)funcs.GetProcAddress(hUser32, strMessageBoxA));

	dprintf((WIN32FUNCS*)&funcs, strDebug, hUser32);
	dprintf((WIN32FUNCS*)&funcs, strDebug, MessageBoxA);

	MessageBoxA(NULL, strHelloWorld, strTest, MB_OK);
}