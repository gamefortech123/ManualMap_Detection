#pragma once
#include "StandardIncludes.hpp"

struct ModuleDump
{
public:
	PVOID ModuleBase;
	int ModuleSize;
	HANDLE hProcess;
	ModuleDump() : ModuleBase(0), ModuleSize(0), hProcess(0) {}
	ModuleDump(PVOID ModuleBase, int ModuleSize, HANDLE hProcess) : ModuleBase(ModuleBase), ModuleSize(ModuleSize), hProcess(hProcess) {}
	bool DumpModule()
	{

		static auto IsValidAddress = [](PVOID Address)->bool
		{
			_MEMORY_BASIC_INFORMATION mbi = { 0,0,0,0,0,0,0 };
			if (!VirtualQuery(Address, &mbi, sizeof(mbi)))
				return false;
			if (mbi.Protect == 0 || mbi.Protect == PAGE_NOACCESS)
				return false;
			return true;
		};


		static auto RtlImageNtHeader = [](PVOID ImageBase)->IMAGE_NT_HEADERS *
		{
			IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);
			if (!IsValidAddress(reinterpret_cast<PVOID>(DosHeader)) ||
				DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
				return false;
			IMAGE_NT_HEADERS* NtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<DWORD_PTR>(ImageBase) + DosHeader->e_lfanew);
			if (!IsValidAddress(reinterpret_cast<PVOID>(NtHeader)) ||
				NtHeader->Signature != IMAGE_NT_SIGNATURE)
				return false;
			return NtHeader;
		};

		char Path[1024];
		PIMAGE_SECTION_HEADER SectionHeaders = 0;
		HANDLE hFile = INVALID_HANDLE_VALUE;
		SIZE_T readSize = 0;
		byte* ModuleData = 0;
		PIMAGE_NT_HEADERS NtHeader = 0;
		unsigned int i = 0, bufPtr = 0;
		ZeroMemory(Path, 1024);
		sprintf_s(Path, "0x%X_%d.dll", ModuleBase, ModuleSize);
		if (!GetFullPathNameA(Path, 1024, Path, 0))
			return false;
		ModuleData = new byte[ModuleSize];
		if (!ModuleData)
			return false;
		if (!ReadProcessMemory(hProcess, ModuleBase, ModuleData, ModuleSize, &readSize) && !readSize)
		{
			delete ModuleData;
			return false;
		}
		hFile = CreateFileA(Path, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			if (!DeleteFileA(Path))
			{
				delete ModuleData;
				return false;
			}
			CloseHandle(hFile);
		}
		hFile = CreateFileA(Path, GENERIC_ALL, 0, 0, CREATE_ALWAYS, 0, 0);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			delete ModuleData;
			return false;
		}
		NtHeader = RtlImageNtHeader(ModuleData);
		SectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(NtHeader + 1);

		bufPtr = NtHeader->OptionalHeader.SizeOfHeaders;

		for (SectionHeaders = IMAGE_FIRST_SECTION(NtHeader); i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeaders)
		{
			SectionHeaders->Misc.VirtualSize = SectionHeaders->SizeOfRawData;

			memcpy(ModuleData + bufPtr, SectionHeaders, sizeof(IMAGE_SECTION_HEADER));
			bufPtr += sizeof(IMAGE_SECTION_HEADER);

			ReadProcessMemory(hProcess, (void*)(NtHeader->OptionalHeader.ImageBase + SectionHeaders->VirtualAddress), ModuleData + SectionHeaders->PointerToRawData, SectionHeaders->SizeOfRawData, NULL);
		}

		if (!WriteFile(hFile, ModuleData, ModuleSize, reinterpret_cast<LPDWORD>(&readSize), 0))
		{
			delete ModuleData;
			CloseHandle(hFile);
			return false;
		}
		delete ModuleData;
		CloseHandle(hFile);
		return true;
	}
};

typedef void(WINAPI* p_CallBack)(ModuleDump Module);


class ModuleScanner
{
public:
	ModuleScanner();
	~ModuleScanner();

	bool Start();
	bool Stop();

	bool setProcess(DWORD pId);
	bool setProcess(HANDLE Process);
	void setCallback(p_CallBack CallBack);

private:

	HANDLE hProcess;
	static DWORD WINAPI ScanThread(LPVOID Argument);
	static p_CallBack cCallBack;
	static HANDLE hThread;

};