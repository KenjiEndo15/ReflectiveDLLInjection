#include "../inc/reflective_loader_operations.h"

PIMAGE_NT_HEADERS getNtHeaders(PVOID dllAddr) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllAddr;
    LONG ntHeaderRva = dosHeader->e_lfanew;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)dllAddr + ntHeaderRva);

    return ntHeaders;
}

PIMAGE_OPTIONAL_HEADER getOptionalHeader(PVOID dllAddr) {
    PIMAGE_NT_HEADERS ntHeaders = getNtHeaders(dllAddr);
    PIMAGE_OPTIONAL_HEADER optionalHeader = &ntHeaders->OptionalHeader;

    return optionalHeader;
}

PIMAGE_DATA_DIRECTORY getDataDirectory(PVOID dllAddr, SIZE_T directoryEntry) {
    PIMAGE_OPTIONAL_HEADER optionalHeader = getOptionalHeader(dllAddr);
    PIMAGE_DATA_DIRECTORY dataDirectory = &(optionalHeader->DataDirectory[directoryEntry]);

    return dataDirectory;
}

PIMAGE_SECTION_HEADER getSectionHeader(PVOID dllAddr) {
    PIMAGE_NT_HEADERS ntHeaders = getNtHeaders(dllAddr);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    return sectionHeader;
}

PIMAGE_EXPORT_DIRECTORY getExportDirectory(PVOID dllAddr) {
    PIMAGE_DATA_DIRECTORY dataDirectory = getDataDirectory(dllAddr, IMAGE_DIRECTORY_ENTRY_EXPORT);
    DWORD virtualAddr = dataDirectory->VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)dllAddr + virtualAddr);

    return exportDirectory;
}

PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor(PVOID dllAddr) {
    PIMAGE_DATA_DIRECTORY dataDirectory = getDataDirectory(dllAddr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    DWORD virtualAddr = dataDirectory->VirtualAddress;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)dllAddr + virtualAddr);

    return importDescriptor;
}

PIMAGE_BASE_RELOCATION getBaseRelocation(PVOID dllAddr) {
    PIMAGE_DATA_DIRECTORY dataDirectory = getDataDirectory(dllAddr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    DWORD virtualAddr = dataDirectory->VirtualAddress;
    PIMAGE_BASE_RELOCATION baseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)dllAddr + virtualAddr);

    return baseReloc;
}

PIMAGE_TLS_DIRECTORY getTlsDirectory(PVOID dllAddr) {
    PIMAGE_DATA_DIRECTORY dataDirectory = getDataDirectory(dllAddr, IMAGE_DIRECTORY_ENTRY_TLS);

    if (dataDirectory->Size == 0) {
        return NULL;
    }

    DWORD virtualAddr = dataDirectory->VirtualAddress;
    PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)((ULONG_PTR)dllAddr + virtualAddr);

    return tlsDirectory;
}

#pragma intrinsic(_ReturnAddress)
PVOID getReturnAddr() {
    return (PVOID)_ReturnAddress();
}

PVOID findBaseAddr(PVOID currentIp) {
    ULONG_PTR peBaseAddr = (ULONG_PTR)currentIp;

    while (TRUE) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peBaseAddr;
        WORD dosSignature = pDosHeader->e_magic;

        if (dosSignature == IMAGE_DOS_SIGNATURE) {
            LONG ntHeadersRva = pDosHeader->e_lfanew;

            if (ntHeadersRva >= sizeof(IMAGE_DOS_HEADER) && ntHeadersRva < 1024) {
                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peBaseAddr + ntHeadersRva);
                DWORD ntSignature = ntHeaders->Signature;

                if (ntSignature == IMAGE_NT_SIGNATURE) {
                    break;
                }
            }
        }

        peBaseAddr--;
    }

    return (PVOID)peBaseAddr;
}

PPEB getPeb() {
    PPEB peb = NULL;

#if defined(_WIN64)
    peb = (PPEB)(__readgsqword(0x60));
#elif defined(_WIN32)
    peb = (PPEB)(__readfsdword(0x30));
#endif

    return peb;
}

PVOID getDllAddr(PWCHAR targetDllName) {
    PPEB peb = getPeb();
    PLIST_ENTRY dllsList = &peb->Ldr->InMemoryOrderModuleList;

    for (PLIST_ENTRY entry = dllsList->Flink; entry != dllsList; entry = entry->Flink) {
        C_PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(
            entry,
            C_LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        UNICODE_STRING currentDll = ldrEntry->BaseDllName;
        PWSTR currentName = currentDll.Buffer;
        SIZE_T nameLength = currentDll.Length / sizeof(WCHAR);

        BOOL namesMatched = TRUE;

        for (SIZE_T i = 0; i <= nameLength; ++i) {
            wchar_t char1 = targetDllName[i];
            wchar_t char2 = currentName[i];

            if (char1 != char2) {
                namesMatched = FALSE;
                break;
            }

            if (char1 == L'\0') break;
        }

        if (namesMatched) {
            return ldrEntry->DllBase;
        }
    }

    return 0;
}

PVOID getFunctionFromDll(PCHAR targetFunctionName, PVOID dllAddr) {
    PIMAGE_EXPORT_DIRECTORY exportDirectory = getExportDirectory(dllAddr);

    DWORD numberOfNames = exportDirectory->NumberOfNames;

    PDWORD addressOfFunctions = (PDWORD)((ULONG_PTR)dllAddr + exportDirectory->AddressOfFunctions);
    PWORD addressOfNameOrdinals = (PWORD)((ULONG_PTR)dllAddr + exportDirectory->AddressOfNameOrdinals);
    PDWORD addressOfNames = (PDWORD)((ULONG_PTR)dllAddr + exportDirectory->AddressOfNames);

    for (DWORD index = 0; index < numberOfNames; index++) {
        LPSTR currentName = (LPSTR)((ULONG_PTR)dllAddr + addressOfNames[index]);
        SIZE_T charCount = 0;

        while (TRUE) {
            char char1 = targetFunctionName[charCount];
            char char2 = currentName[charCount];

            if (char1 != char2) {
                break;
            }

            if (char1 == 0 && char2 == 0) {
                WORD ordinalValue = addressOfNameOrdinals[index];
                DWORD relativeFunctionAddr = addressOfFunctions[ordinalValue];
                PVOID functionAddr = (PVOID)((ULONG_PTR)dllAddr + relativeFunctionAddr);

                return functionAddr;
            }

            charCount++;
        }
    }

    return 0;
}

PVOID getKernel32Addr() {
    wchar_t kernel32Name[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'D', 'L', 'L', 0 };
    return getDllAddr(kernel32Name);
}

PVOID getLoadLibraryAAddr(PVOID dllAddr) {
    char loadLibraryAName[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    return getFunctionFromDll(loadLibraryAName, dllAddr);
}

PVOID getVirtualAllocAddr(PVOID dllAddr) {
    char virtualAllocName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
    return getFunctionFromDll(virtualAllocName, dllAddr);
}

PVOID getVirtualProtectAddr(PVOID dllAddr) {
    char virtualProtectName[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0 };
    return getFunctionFromDll(virtualProtectName, dllAddr);
}

PVOID getGetProcAddressAddr(PVOID dllAddr) {
    char getProcAddressName[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
    return getFunctionFromDll(getProcAddressName, dllAddr);
}

PVOID getFlushInstructionCache(PVOID dllAddr) {
    char flushInstructionCacheName[] = { 'F', 'l', 'u', 's', 'h', 'I', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 'C', 'a', 'c', 'h', 'e', 0 };
    return getFunctionFromDll(flushInstructionCacheName, dllAddr);
}

PVOID allocateMemoryDll(PVOID unloadedDllAddr, _VirtualAlloc virtualAlloc) {
    PIMAGE_OPTIONAL_HEADER optionalHeader = getOptionalHeader(unloadedDllAddr);
    DWORD sizeOfImage = optionalHeader->SizeOfImage;

    PVOID loadedDllAddr = (PVOID)(
        virtualAlloc(
            NULL,
            sizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        ));

    return loadedDllAddr;
}

VOID copyHeaders(PVOID srcDllAddr, PVOID destDllAddr) {
    PIMAGE_OPTIONAL_HEADER optionalHeader = getOptionalHeader(srcDllAddr);
    DWORD sizeOfHeaders = optionalHeader->SizeOfHeaders;

    for (DWORD i = 0; i < sizeOfHeaders; i++) {
        ((BYTE*)destDllAddr)[i] = ((BYTE*)srcDllAddr)[i];
    }
}

VOID copySections(PVOID srcDllAddr, PVOID destDllAddr) {
    PIMAGE_NT_HEADERS ntHeaders = getNtHeaders(srcDllAddr);
    WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeader = getSectionHeader(srcDllAddr);

    for (WORD i = 0; i < numberOfSections; ++i) {

        DWORD virtualAddr = sectionHeader->VirtualAddress;
        PVOID destSectionAddr = (PVOID)((ULONG_PTR)destDllAddr + virtualAddr);

        DWORD pointerToRawData = sectionHeader->PointerToRawData;
        PVOID srcSectionAddr = (PVOID)((ULONG_PTR)srcDllAddr + pointerToRawData);
        DWORD sizeOfRawData = sectionHeader->SizeOfRawData;

        for (DWORD j = 0; j < sizeOfRawData; ++j) {
            ((BYTE*)destSectionAddr)[j] = ((BYTE*)srcSectionAddr)[j];
        }

        ++sectionHeader;
    }
}

VOID initializeIAT(PVOID dllAddr, _LoadLibraryA loadLibraryA, _GetProcAddress getProcAddress) {
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = getImportDescriptor(dllAddr);

    while (importDescriptor->Name != 0) {
        DWORD nameRva = importDescriptor->Name;
        LPCSTR libraryName = (LPCSTR)((ULONG_PTR)dllAddr + nameRva);
        HMODULE dllHandle = loadLibraryA(libraryName);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)dllAddr + importDescriptor->FirstThunk);

        while (thunk->u1.AddressOfData != 0) {
            LPCSTR functionData = NULL;

            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                functionData = (LPCSTR)(IMAGE_ORDINAL(thunk->u1.Ordinal));
            }
            else {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)dllAddr + thunk->u1.AddressOfData);
                functionData = importByName->Name;
            }

            thunk->u1.Function = (ULONGLONG)(getProcAddress(dllHandle, functionData));
            ++thunk;
        }
        ++importDescriptor;
    }
}

VOID performRelocations(PVOID dllAddr) {
    PIMAGE_OPTIONAL_HEADER optionalHeader = getOptionalHeader(dllAddr);
    ULONG_PTR delta = (ULONG_PTR)dllAddr - optionalHeader->ImageBase;

    PIMAGE_BASE_RELOCATION baseReloc = getBaseRelocation(dllAddr);

    while (baseReloc->VirtualAddress != 0) {
        DWORD pageRva = baseReloc->VirtualAddress;
        DWORD sizeOfBlock = baseReloc->SizeOfBlock;

        SIZE_T totalRelocEntries = (sizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PBASE_RELOCATION_ENTRY baseRelocEntry = (PBASE_RELOCATION_ENTRY)(baseReloc + 1);

        for (SIZE_T i = 0; i < totalRelocEntries; i++) {
            WORD relocType = baseRelocEntry[i].Type;
            WORD relocOffsetRva = baseRelocEntry[i].Offset;

            DWORD relocationRva = relocOffsetRva + pageRva;
            ULONG_PTR addrToRelocate = (ULONG_PTR)dllAddr + relocationRva;

            switch (relocType) {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                *(DWORD*)addrToRelocate += (DWORD)delta;
                break;
            case IMAGE_REL_BASED_DIR64:
                *(ULONG_PTR*)addrToRelocate += delta;
                break;
            }
        }
        baseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)baseReloc + sizeOfBlock);
    }
}

VOID applySectionsProtections(PVOID dllAddr, _VirtualProtect virtualProtect) {
    PIMAGE_NT_HEADERS ntHeaders = getNtHeaders(dllAddr);
    WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeader = getSectionHeader(dllAddr);

    DWORD protection = 0;

    for (WORD i = 0; i < numberOfSections; ++i) {

        DWORD virtualAddr = sectionHeader->VirtualAddress;
        PVOID sectionAddr = (PVOID)((ULONG_PTR)dllAddr + virtualAddr);

        DWORD sizeOfSection = sectionHeader->Misc.VirtualSize;
        DWORD characteristics = sectionHeader->Characteristics;

        BOOL isExecutable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL isReadable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOL isWritable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (isExecutable && isWritable && isReadable) {
            protection = PAGE_EXECUTE_READWRITE;
        }
        else if (isExecutable && isReadable) {
            protection = PAGE_EXECUTE_READ;
        }
        else if (isExecutable && isWritable) {
            protection = PAGE_EXECUTE_WRITECOPY;
        }
        else if (isExecutable) {
            protection = PAGE_EXECUTE;
        }
        else if (isWritable && isReadable) {
            protection = PAGE_READWRITE;
        }
        else if (isWritable) {
            protection = PAGE_WRITECOPY;
        }
        else if (isReadable) {
            protection = PAGE_READONLY;
        }
        else {
            protection = PAGE_NOACCESS;
        }

        virtualProtect(sectionAddr, sizeOfSection, protection, &protection);
        ++sectionHeader;
    }
}

VOID runTlsCallbacks(PVOID dllAddr) {
    PIMAGE_TLS_DIRECTORY tlsDirectory = getTlsDirectory(dllAddr);

    if (tlsDirectory != NULL) {
        PIMAGE_TLS_CALLBACK callbackArray = (PIMAGE_TLS_CALLBACK)tlsDirectory->AddressOfCallBacks;
        PIMAGE_TLS_CALLBACK* currentCallback = callbackArray;

        while (*currentCallback != NULL) {
            PIMAGE_TLS_CALLBACK callbackFunc = *currentCallback;
            callbackFunc(dllAddr, DLL_PROCESS_ATTACH, NULL);

            currentCallback++;
        }
    }
}

PVOID getDllEntryPoint(PVOID dllAddr) {
    PIMAGE_OPTIONAL_HEADER optionalHeader = getOptionalHeader(dllAddr);
    DWORD addressOfEntryPoint = optionalHeader->AddressOfEntryPoint;
    PVOID dllEntryPoint = ((ULONG_PTR)dllAddr + addressOfEntryPoint);

    return dllEntryPoint;
}