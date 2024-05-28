# HideStaticReferences - Static Reference Remover (Proof of concept)

## What is this?  
An example in C/C++ of how we can remove static string & function call references by using obfuscation paired with runtime function pointers. As a result, static analysis using tools such as IDA and x64dbg becomes more difficult. You may even be able to hide specific API calls from anti-malware or anti-cheat systems (for example, calls to `ShellExecuteA/W`). Some AVs might also flag this behavior as being malicious.

## How it works  
A couple of techniques are used in order to hide static references to strings & API calls: all string variables are made on the stack and XOR'd with an inline function (acting the same as a macro) at compile time. WINAPI call references can be removed by calling them at run-time through function pointers. Combining both techniques implies that we are calling function pointers which have had their addresses fetched dynamically from the export directory table (using a masked string), and as a result no explicit references will be made to these functions or strings. An example can be found in the 'HideStaticReferences.cpp' file.

## Requirements  
/O2 optimization is highly recommended, or else some string character artifacts might be viewable through a disassembly view. /O2 packs multiple characters into a single opcode (instead of just one character) and thus strings become more difficult to visualize; if you're encrypting them properly at compile-time there should be no plaintext traces.

## Further Recommendations  
- Calls to `GetModuleHandle` are a possible detection artifact and can be replaced with grabbing this data from the PEB. Calls to `GetProcAddress` have now been replaced with _GetProcAddress, which grabs function addresses by traversing the export directory table.

- A library with a premade set of function pointers for all APIs in KERNEL32 can be made for easier implementation in larger projects  


## Visual Examples
Below we can see a screenshot of how disassembly looks when working with this technique: No strings should be viewable in plain sight and thus an attacker cannot easily find our function by string scanning using popular tools. The top graph block in IDA shows the encrypted string being placed into offsets of RBP register. While it may appear as if some characters are present there, these are not the original string and translate to gibberish until its been decrypred. The bottom graph block shows the decryption routine (xor instruction with loop). When viewing static API calls, close to zero entries should show up.

![ida_view_O2](https://github.com/AlSch092/HideStaticReferences/assets/94417808/f5a1dafd-383a-4d42-a8a9-c05bed3d4a09)
