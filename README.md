# ReflectiveDLLInjection
Stephen Fewer created the original [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection). I decided to learn how to do it myself, with a cleaner codebase and added features.

## shellcode RDI
I rewrote the [sRDI](https://github.com/monoxgas/sRDI) project, but did not push it. The same goes for [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode). These projects are not that different from Stephen Fewer's one.

Some interesting facts stem from the way the executable code is extracted. The former makes use of a [function link order](https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/function_link_order.txt) while the latter make use of the [masm_shc](https://github.com/hasherezade/masm_shc) utility for producing shellcode.

## Schemas
Here are some schemas to understand PE parsing (there may be some errors).

**[!] Images should be viewed in light mode.**

### getDllAddr
The [getDllAddr](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/src/reflective_loader_operations.c#L112-L147) function retrieves a process-loaded DLL based on the [PEB](https://alice.climent.red/posts/direct-syscalls-hells-halos-syswhispers2/#retrieving-windows-dll-addresses-the-process-environment-block-peb).

![alt text](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/schemas/1.drawio.svg "2")

### getFunctionFromDll
The [getFunctionFromDll](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/src/reflective_loader_operations.c#L149-L183) function parses the [Export Address Table (EAT)](https://alice.climent.red/posts/direct-syscalls-hells-halos-syswhispers2/#retrieving-windows-api-functions-addresses-parsing-the-export-address-table-eat) to retrieve a function from a DLL.

![alt text](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/schemas/2.drawio.svg "2")

### copyHeaders
The [copyHeaders](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/src/reflective_loader_operations.c#L230-L237) function copies the headers from the unloaded DLL to a previously allocated virtual memory region.

![alt text](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/schemas/3.drawio.svg "3")

### copySections
The [copySections](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/src/reflective_loader_operations.c#L239-L259) function copies the sections from the unloaded DLL to a previously allocated virtual memory region.

![alt text](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/schemas/4.drawio.svg "4")

### initializeIAT
The [initializeIAT](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/src/reflective_loader_operations.c#L261-L286) function parses the [Import Address Table (IAT)](https://alice.climent.red/posts/how-and-why-to-unhook-the-import-address-table/) to update function pointer addresses.

![alt text](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/schemas/5.drawio.svg "5")

### performRelocations
The [performRelocations](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/src/reflective_loader_operations.c#L288-L321) function resolves [relocations](https://0xrick.github.io/win-internals/pe7/).

![alt text](https://github.com/KenjiEndo15/ReflectiveDLLInjection/blob/main/schemas/6.drawio.svg "6")

## Improvements
A non-exhaustive list:
- Use `HRESULT` for cleaner error handling.
- Manage Delay Load Imports (not that important I think).
- Manage the Exception Table the way [Rhadamanthys](https://research.checkpoint.com/2023/from-hidden-bee-to-rhadamanthys-the-evolution-of-custom-executable-formats/) does.
- ...

## Evasion
There are no evasion features in this code.
