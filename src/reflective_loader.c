#include "../inc/reflective_loader_operations.h"

#include <stdio.h>

VOID reflectiveLoader(PVOID unloadedDllAddr) {
	PVOID kernel32Addr = getKernel32Addr();

	PVOID loadLibraryAAddr = getLoadLibraryAAddr(kernel32Addr);
	PVOID virtualAllocAddr = getVirtualAllocAddr(kernel32Addr);
	PVOID virtualProtectAddr = getVirtualProtectAddr(kernel32Addr);
	PVOID getProcAddressAddr = getGetProcAddressAddr(kernel32Addr);
	PVOID flushInstructionCacheAddr = getFlushInstructionCache(kernel32Addr);

	_LoadLibraryA loadLibraryA = (_LoadLibraryA)loadLibraryAAddr;
	_VirtualAlloc virtualAlloc = (_VirtualAlloc)virtualAllocAddr;
	_VirtualProtect virtualProtect = (_VirtualProtect)virtualProtectAddr;
	_GetProcAddress getProcAddress = (_GetProcAddress)getProcAddressAddr;
	_FlushInstructionCache flushInstructionCache = (_FlushInstructionCache)flushInstructionCacheAddr;

	//PVOID currentIp = getReturnAddr();
	//PVOID unloadedDllAddr = findBaseAddr(currentIp);

	PVOID loadedDllAddr = allocateMemoryDll(unloadedDllAddr, virtualAlloc);
	copyHeaders(unloadedDllAddr, loadedDllAddr);
	copySections(unloadedDllAddr, loadedDllAddr);

	initializeIAT(loadedDllAddr, loadLibraryA, getProcAddress);
	performRelocations(loadedDllAddr);
	applySectionsProtections(loadedDllAddr, virtualProtect);
	runTlsCallbacks(loadedDllAddr);

	flushInstructionCache((HANDLE)-1, NULL, 0);

	PVOID dllEntryPoint = getDllEntryPoint(loadedDllAddr);
	((_DllMain)dllEntryPoint)((HINSTANCE)loadedDllAddr, DLL_PROCESS_ATTACH, NULL);
}

PVOID readDllFromDisk(LPCSTR dllName) {
	LPVOID dllAddr = NULL;

	HANDLE dllHandle = CreateFileA(dllName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (dllHandle == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA failed with error: %ld\n", GetLastError());
		goto _END_OF_FUNC;
	}

	SIZE_T dllSize = GetFileSize(dllHandle, NULL);
	if (dllSize == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize failed with error: %ld\n", GetLastError());
		goto _END_OF_FUNC;
	}

	dllAddr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
	if (!dllAddr) {
		printf("[!] HeapAlloc failed with error: %ld\n", GetLastError());
		goto _END_OF_FUNC;
	}

	LPDWORD numberOfBytesRead = 0;

	BOOL isReadFile = ReadFile(dllHandle, dllAddr, (DWORD)dllSize, &numberOfBytesRead, NULL);
	if (!isReadFile) {
		printf("[!] ReadFile failed with error: %d\n", GetLastError());
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (dllHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(dllHandle);
	}

	if (dllAddr) {
		return (PVOID)dllAddr;
	}

	return NULL;
}

int main(int argc, char** argv) {
	if (argc < 1) {
		printf("Usage: %s <dll_file.dll>\n", argv[0]);
		printf("Example: %s C:\\Temp\\message_box.dll\n", argv[0]);
		return 1;
	}

	LPSTR dllName = argv[1];

	PVOID unloadedDllAddr = readDllFromDisk(dllName);
	if (!unloadedDllAddr) {
		printf("[!] readDllFromDisk failed.");
		return 1;
	}

	reflectiveLoader(unloadedDllAddr);
	return 0;
}