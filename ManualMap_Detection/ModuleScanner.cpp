#include "ModuleScanner.hpp"

HANDLE ModuleScanner::hThread;
p_CallBack ModuleScanner::cCallBack;

ModuleScanner::ModuleScanner()
{
	cCallBack = 0;
}
ModuleScanner::~ModuleScanner()
{

}

bool ModuleScanner::Start()
{
	if (!cCallBack || hThread)
		return false;
	hThread = CreateThread(0, 0, ScanThread, hProcess, 0, 0);
	return hThread ? true : false;
}
bool ModuleScanner::Stop()
{
	return TerminateThread(hThread, 0);
}

bool ModuleScanner::setProcess(DWORD pId)
{
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pId);
	return (hProcess != INVALID_HANDLE_VALUE);
}

bool ModuleScanner::setProcess(HANDLE Process)
{
	hProcess = Process;
	return true;
}

void ModuleScanner::setCallback(p_CallBack CallBack)
{
	cCallBack = CallBack;
}

DWORD WINAPI ModuleScanner::ScanThread(LPVOID Argument)
{
	DWORD_PTR dwAddress = 0, dwModule = 0;
	_MEMORY_BASIC_INFORMATION mbi = { 0,0,0,0,0,0,0 };
	BYTE* Page = 0;
	IMAGE_NT_HEADERS* PE = 0;

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
		if (!DosHeader ||
			DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return false;
		IMAGE_NT_HEADERS* NtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<DWORD_PTR>(ImageBase) + DosHeader->e_lfanew);
		if (!IsValidAddress(reinterpret_cast<PVOID>(NtHeader)) ||
			NtHeader->Signature != IMAGE_NT_SIGNATURE)
			return false;
		return NtHeader;
	};

	auto IsImageInsidePage = [](PVOID Page, DWORD Size)->DWORD_PTR
	{
		DWORD_PTR dwStart = reinterpret_cast<DWORD_PTR>(Page);
		DWORD_PTR dwEnd = dwStart + Size;
		while (dwStart <= dwEnd)
		{
			if (RtlImageNtHeader(reinterpret_cast<PVOID>(dwStart)))
				return dwStart;
			dwStart++;
		}
		return false;
	};

	while (VirtualQueryEx(Argument, reinterpret_cast<LPCVOID>(dwAddress), &mbi, sizeof(mbi)))
	{
		if (mbi.Protect == 0 || mbi.Protect == PAGE_NOACCESS)
			goto continue_loop;
		Page = new byte[mbi.RegionSize];
		if (!Page)
			return false;
		if (ReadProcessMemory(Argument, reinterpret_cast<LPCVOID>(dwAddress), Page, mbi.RegionSize, 0))
		{
			dwModule = IsImageInsidePage(Page, mbi.RegionSize);
			if (dwModule)
			{
				PE = RtlImageNtHeader(reinterpret_cast<PVOID>(dwModule));
				cCallBack(ModuleDump(reinterpret_cast<LPVOID>((dwModule - reinterpret_cast<DWORD_PTR>(Page)) + dwAddress), PE->OptionalHeader.SizeOfImage, Argument));
			}
		}
		if (Page) delete Page;
		Page = 0;
	continue_loop:
		dwAddress = reinterpret_cast<DWORD_PTR>(mbi.BaseAddress) + mbi.RegionSize;
	}
	return true;
}