# ReflectiveDLLInjection
Stephen Fewer created the original [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection). I decided to learn how to do it myself, with a cleaner codebase and added features.

## shellcode RDI
I rewrote the [sRDI](https://github.com/monoxgas/sRDI) project, but did not push it. Same goes for [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode).

These projects are not that different from Stephen Fewer's one. Some interesting facts stem from the way the executable code is extracted. The former make use of a [function link order](https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/function_link_order.txt) while the latter make use of the [masm_shc](https://github.com/hasherezade/masm_shc) utility for producing a shellcode.

## Improvements
A non-exhaustive list:
- Use `HRESULT` for cleaner error handling.
- Manage Delay Load Imports (not that important in my opinion).
- Manage the Exception Table the way [Rhadamanthys](https://research.checkpoint.com/2023/from-hidden-bee-to-rhadamanthys-the-evolution-of-custom-executable-formats/) does.
- ...

## Evasion
There are no evasion features in this code.
