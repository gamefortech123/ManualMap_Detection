#include "ModuleScanner.hpp"



void WINAPI CallBack(ModuleDump Dump)
{

	auto IsModuleInsidePEB = [](HMODULE hModule)->BOOL
	{
		typedef struct _PEB_LDR_DATA2 {
			ULONG      Length;
			BOOLEAN    Initialized;
			PVOID      SsHandle;
			LIST_ENTRY InLoadOrderModuleList;
			LIST_ENTRY InMemoryOrderModuleList;
			LIST_ENTRY InInitializationOrderModuleList;
		} PEB_LDR_DATA2, * PPEB_LDR_DATA2;


		typedef struct _PEB2 {
#ifdef _WIN64
			UINT8 _PADDING_[24];
#else
			UINT8 _PADDING_[12];
#endif
			PEB_LDR_DATA2* Ldr;
		} PEB2, * PPEB2;
		typedef struct _LDR_MODULE
		{
			LIST_ENTRY      InLoadOrderModuleList;
			LIST_ENTRY      InMemoryOrderModuleList;
			LIST_ENTRY      InInitializationOrderModuleList;
			PVOID           BaseAddress;
			PVOID           EntryPoint;
			ULONG           SizeOfImage;
			UNICODE_STRING  FullDllName;
			UNICODE_STRING  BaseDllName;
			ULONG           Flags;
			SHORT           LoadCount;
			SHORT           TlsIndex;
			LIST_ENTRY      HashTableEntry;
			ULONG           TimeDateStamp;
		} LDR_MODULE, * PLDR_MODULE;

#ifdef _WIN64
		PPEB2 pPEB = reinterpret_cast<PPEB2>(__readgsqword(0x60));
#else
		PPEB2 pPEB = reinterpret_cast<PPEB2>(__readfsdword(0x30));
#endif
		PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		PLDR_MODULE Current = NULL;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != NULL)
		{
			Current = CONTAINING_RECORD(CurrentEntry, LDR_MODULE, InLoadOrderModuleList);
			if (Current->BaseAddress == hModule)
				return true;
			CurrentEntry = CurrentEntry->Flink;
		}
		return false;
	};

	auto IsWhitelisted = [](PVOID lpDll)->bool
	{
		if (lpDll == 0)
			return false;

		PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<DWORD_PTR>(lpDll) + PIMAGE_DOS_HEADER(lpDll)->e_lfanew));

		if (!NtHeaders ||
			NtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return false;
#if defined _M_X64
#elif defined _M_IX86 
		if (NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
			NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
		{
			return true;
		}
#endif
		return false;
	};

	// If the found module is not inside the PEB probably means it's mapped
	if (!IsModuleInsidePEB(reinterpret_cast<HMODULE>(Dump.ModuleBase)))
	{
		// We may need to whitelist some modules.
		if (!IsWhitelisted(Dump.ModuleBase))
		{
			std::cout << "Manual mapped module found : " << Dump.ModuleBase << std::endl;
			return;
		}
	}
	std::cout << "Module found : " << Dump.ModuleBase << std::endl;
}

int main()
{
	ModuleScanner Scanner;
	Scanner.setCallback(CallBack);

	if (!Scanner.setProcess(GetCurrentProcessId()))
	{
		std::cout << "setProcess failed with errorcode " << GetLastError() << std::endl;
		std::cin.get();
	}
	if (!Scanner.Start())
	{
		std::cout << "Start failed with errorcode " << GetLastError() << std::endl;
		std::cin.get();
	}

	std::cin.get();

}
