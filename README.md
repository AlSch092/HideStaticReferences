# HideStaticReferences - Static Reference Remover (Proof of concept)

## What is this?  
An example in C/C++ of how we can remove static string & function call references by using obfuscation paired with runtime function pointers. As a result, static analysis using tools such as IDA and x64dbg becomes more difficult. You may even be able to hide specific API calls from anti-malware or anti-cheat systems (for example, calls to ShellExecuteA/W). This technique can also be combined with packing or shellcode injection for an added layer of security.

## How it works  
A couple of techniques are used in order to hide static references to strings & API calls: all string variables are made on the stack and XOR'd with an inline function (acting the same as a macro) at compile time. WINAPI call references can be removed by calling them at run-time through function pointers. Combining both techniques implies that we are calling function pointers which have had their addresses fetched using `GetProcAddress` with a masked string, and as a result no explicit references will be made to these functions or strings. An example can be found in the 'HideStaticReferences.cpp' file.

## Requirements  
/O2 optimization is highly recommended, or else some string's character artifacts will be viewable through a disassembly viewer. /O2 packs multiple characters into a single opcode (instead of just one character) and thus strings become more difficult to visualize, and tools won't auto-display any characters. 

## Further Recommendations  
-Calls to `GetModuleHandle` is a possible detection artifact and can be replaced with grabbing this data from the PEB. Calls to `GetProcAddress` have now been replaced with _GetProcAddress, which grabs function addresses by traversing the export directory table.
-A library with a premade set of function pointers for all APIs in KERNEL32 can be made for easier implementation in larger projects  
-The 'xor' routine can be made more complex by adding/subtracting a constant on each alternating digit, which will stop XOR brute forcing tools.

## Screenshot:
Below we can see a screenshot of how disassembly looks when working with this technique: No strings should be viewable in plain sight and thus an attacker cannot easily find our function by string scanning using popular tools.

![ida_view_O2](https://github.com/AlSch092/HideStaticReferences/assets/94417808/f5a1dafd-383a-4d42-a8a9-c05bed3d4a09)
