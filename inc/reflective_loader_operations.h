#ifndef REFLECTIVE_LOADER_OPERATIONS_H
#define REFLECTIVE_LOADER_OPERATIONS_H

#include <intrin.h>
#include <windows.h>
#include <winternl.h>

typedef struct C_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID      DllBase;
	PVOID      EntryPoint;
	ULONG      SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG      Flags;
	USHORT     LoadCount;
	USHORT     TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID      SectionPointer;
	ULONG      CheckSum;
	ULONG      TimeDateStamp;
	PVOID      LoadedImports;
	PVOID      EntryPointActivationContext;
	PVOID      PatchInformation;
} C_LDR_DATA_TABLE_ENTRY, * C_PLDR_DATA_TABLE_ENTRY;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct IMAGE_RELOC {
	WORD offset : 12;
	WORD type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef HMODULE(WINAPI* _LoadLibraryA)(
	LPCSTR lpLibFileName
	);

typedef LPVOID(WINAPI* _VirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

typedef LPVOID(WINAPI* _VirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD  lpflOldProtect
	);

typedef FARPROC(WINAPI* _GetProcAddress)(
	HMODULE hModule,
	LPCSTR  lpProcName
	);

typedef BOOL(WINAPI* _FlushInstructionCache)(
	HANDLE hProcess,
	LPCVOID lpBaseAddress,
	SIZE_T dwSize
	);

typedef BOOL(APIENTRY* _DllMain)(
	HMODULE hModule,
	DWORD   ul_reason_for_call,
	LPVOID  lpReserved
	);

PIMAGE_NT_HEADERS getNtHeaders(PVOID dllAddr);
PIMAGE_OPTIONAL_HEADER getOptionalHeader(PVOID dllAddr);
PIMAGE_DATA_DIRECTORY getDataDirectory(PVOID dllAddr, SIZE_T directoryEntry);
PIMAGE_SECTION_HEADER getSectionHeader(PVOID dllAddr);
PIMAGE_EXPORT_DIRECTORY getExportDirectory(PVOID dllAddr);
PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor(PVOID dllAddr);
PIMAGE_BASE_RELOCATION getBaseRelocation(PVOID dllAddr);
PIMAGE_TLS_DIRECTORY getTlsDirectory(PVOID dllAddr);

__declspec(noinline) PVOID getReturnAddr();
PVOID findBaseAddr(PVOID currentIp);

PPEB getPeb();
PVOID getDllAddr(PWCHAR targetDllName);
PVOID getFunctionFromDll(PCHAR targetFunctionName, PVOID dllAddr);

PVOID getKernel32Addr();
PVOID getLoadLibraryAAddr(PVOID dllAddr);
PVOID getVirtualAllocAddr(PVOID dllAddr);
PVOID getVirtualProtectAddr(PVOID dllAddr);
PVOID getGetProcAddressAddr(PVOID dllAddr);
PVOID getFlushInstructionCache(PVOID dllAddr);

PVOID allocateMemoryDll(PVOID unloadedDllAddr, _VirtualAlloc virtualAlloc);
VOID copyHeaders(PVOID srcDllAddr, PVOID destDllAddr);
VOID copySections(PVOID srcDllAddr, PVOID destDllAddr);

VOID initializeIAT(PVOID dllAddr, _LoadLibraryA loadLibraryA, _GetProcAddress getProcAddress);
VOID performRelocations(PVOID dllAddr);
VOID applySectionsProtections(PVOID dllAddr, _VirtualProtect virtualProtect);

VOID runTlsCallbacks(PVOID dllAddr);

PVOID getDllEntryPoint(PVOID dllAddr);

#endif // REFLECTIVE_LOADER_OPERATIONS_H