//HideAPICalls -> Proof of concept to test how we can hide references to APIs from static analysis
//By AlSch092 @ github, Dec. 25 2023, Last Updated Jan 18, 2024.

//Results: Project contains 0 string references and references to certain WINAPIs are removed completely
//Requirements: x64 Target Arch, /O2 optimization (or else string artifacts are revealed when viewing disassembly opcodes)

#include <windows.h>
#include <ImageHlp.h>
#include <stdio.h>
#pragma comment(lib, "ImageHlp")

#define XOR_STRING(input, key) { size_t i; size_t len = strlen(input); for (i = 0; i < len; ++i) { input[i] = (input)[i] ^= (key); } } //this method can get more complex, such as each alternating digit xor's with a different key or adds/subtracts after XORing

__forceinline char XOR(char a, unsigned char key) //need to use __forceinline, just 'inline' did not do the trick!
{
	return a ^= key;
}

//Replacement for GetProcAddress, such that static references won't show up to `GetProcAddress`.
FARPROC _GetProcAddress(PCSTR Module, LPCSTR lpProcName)
{
	DWORD* dNameRVAs(0); //array: addresses of export names
	DWORD* dFunctionRVAs(0);
	WORD* dOrdinalRVAs(0);

	_IMAGE_EXPORT_DIRECTORY* ImageExportDirectory = NULL;
	unsigned long cDirSize = 0;
	_LOADED_IMAGE LoadedImage;
	char* sName = NULL;

	UINT64 AddressFound = NULL;

	UINT64 ModuleBase = (UINT64)GetModuleHandleA(Module); //last remaining artifacts for detection. TODO: Use PEB to fetch this instead of API

	if (!ModuleBase)
		return NULL;

	if (MapAndLoad(Module, NULL, &LoadedImage, TRUE, TRUE))
	{
		ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

		if (ImageExportDirectory != NULL)
		{
			dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);
			dFunctionRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfFunctions, NULL);
			dOrdinalRVAs = (WORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNameOrdinals, NULL);

			for (size_t i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
			{
				sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);					
				
				if (strcmp(sName, lpProcName) == 0) 
				{
					AddressFound = ModuleBase + dFunctionRVAs[dOrdinalRVAs[i]];;
					break;
				}
			}
		}
		else
		{		
			UnMapAndLoad(&LoadedImage);
			return NULL;
		}

		UnMapAndLoad(&LoadedImage);
	}
	
	return (FARPROC)AddressFound;
}

void HiddenMessageBox()
{
	//Each letter is xor'd with an inline function, lets us still see what each string's value is while xor'ing it at compile time. no plaintext is left over from this
	// we use the stack instead of the heap intentionally to help hide, all that's left is some instructions moving 'gibberish' into rsp+X

	//"KERNEL32.DLL"
	char k32[] = { XOR('K', 0x69), XOR('E', 0x69), XOR('R', 0x69), XOR('N', 0x69), XOR('E', 0x69), XOR('L', 0x69), XOR('3', 0x69), XOR('2', 0x69), XOR('.', 0x69), XOR('D', 0x69), XOR('L', 0x69), XOR('L', 0x69), 0x00 };
	//USER32.DLL
	char user32[] = { XOR('U', 0x69), XOR('S', 0x69), XOR('E', 0x69), XOR('R', 0x69), XOR('3', 0x69), XOR('2', 0x69), XOR('.', 0x69), XOR('D', 0x69), XOR('L', 0x69), XOR('L', 0x69), XOR('\0', 0x00) };
	//"MessageBoxA"
	char msgboxA[] = { XOR('M', 0x11), XOR('e', 0x11), XOR('s', 0x11), XOR('s', 0x11), XOR('a', 0x11), XOR('g', 0x11), XOR('e', 0x11), XOR('B', 0x11), XOR('o', 0x11), XOR('x', 0x11), XOR('A', 0x11), 0x00 };
	//"GetProcAddress"
	char getprocaddress[] = { XOR('G', 0x15), XOR('e', 0x15), XOR('t', 0x15), XOR('P', 0x15), XOR('r', 0x15), XOR('o', 0x15), XOR('c', 0x15), XOR('A', 0x15), XOR('d', 0x15), XOR('d', 0x15), XOR('r', 0x15), XOR('e', 0x15), XOR('s', 0x15), XOR('s', 0x15), 0x00 };

	// XORing the string at compile time, very awkward and clunky, sadly don't think there's any compile-time solutions for this since we need to use initializer lists (macros won't work for this in MSVC, i'd love to be proven wrong though!).
	XOR_STRING(k32, 0x69);
	XOR_STRING(user32, 0x69);
	XOR_STRING(msgboxA, 0x11);
	XOR_STRING(getprocaddress, 0x15);

	XOR_STRING(k32, 0x69);

	if (LoadLibraryA(user32)) //would be nice to get rid of loadlibrary calls too, or rely on modules which are already loaded in mem
	{
		typedef int(*_MessageBoxA)(HWND, char*, char*, int);
		_MessageBoxA __MessageBoxA = (_MessageBoxA)_GetProcAddress(user32, msgboxA);

		XOR_STRING(user32, 0x69); //re-mask values to values they were before as soon as it's possible to
		XOR_STRING(msgboxA, 0x11);

		if (__MessageBoxA != (_MessageBoxA)NULL)
		{
			char hello_message[] = { XOR('H', 0x25), XOR('e', 0x25), XOR('l', 0x25), XOR('l', 0x25), XOR('o', 0x25), 0x00 }; //"Hello"
			XOR_STRING(hello_message, 0x25);
			__MessageBoxA(0, hello_message, 0, 0); //Our "Secret" function
		}
	}
}

int main(int argc, char** argv)
{
	HiddenMessageBox();
	return 0;
}
