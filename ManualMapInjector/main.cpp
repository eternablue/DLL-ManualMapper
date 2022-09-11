#include <stdio.h>

#include "util.hpp"

typedef BOOL(__stdcall* dll_main)(HMODULE, DWORD, void*);

typedef	struct _MMAP_DATA_STRUCTURE
{
	void* image_base;
	HMODULE(__stdcall* LoadLibraryA_address)(LPCSTR);
	FARPROC(__stdcall* GetProcAddress_address)(HMODULE, LPCSTR);

} MMAP_DATA_STRUCTURE, *PMMAP_DATA_STRUCTURE;


void load_library_implementation(PMMAP_DATA_STRUCTURE manual_mapping_data)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)manual_mapping_data->image_base;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((char*)dos_header + dos_header->e_lfanew);
	PIMAGE_OPTIONAL_HEADER optional_header = (PIMAGE_OPTIONAL_HEADER)&nt_header->OptionalHeader;

	char* base_address = (char*)(manual_mapping_data->image_base);

	if (optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base_address + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (import_descriptor->Name)
		{
			const char* szMod = (const char*)(base_address + import_descriptor->Name);
			HINSTANCE hDll = manual_mapping_data->LoadLibraryA_address(szMod);

			uint64_t* thunk_reference = (uint64_t*)(base_address + import_descriptor->OriginalFirstThunk);
			uint64_t* function_reference = (uint64_t*)(base_address + import_descriptor->FirstThunk);

			if (!thunk_reference)
				thunk_reference = function_reference;

			for (; *thunk_reference; thunk_reference++, function_reference++)
			{
				if (*thunk_reference & IMAGE_ORDINAL_FLAG)
					*function_reference = (uint64_t)(manual_mapping_data->GetProcAddress_address(hDll, MAKEINTRESOURCEA(*thunk_reference)));
				else
				{
					PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)(base_address + *thunk_reference);
					*function_reference = (uint64_t)(manual_mapping_data->GetProcAddress_address(hDll, pImport->Name));
				}
			}
			import_descriptor++;
		}
	}

	if (optional_header->AddressOfEntryPoint)
	{
		dll_main entry_point = (dll_main)(base_address + optional_header->AddressOfEntryPoint);
		entry_point((HMODULE)(manual_mapping_data->image_base), DLL_PROCESS_ATTACH, 0);
	}
}

void __stdcall stub() 
{

}


void main(int argc, char* argv[])
{
	HANDLE hFile = CreateFileA(&(*argv[2]), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hFile)
		printf("[+] Opened handle 0x%X to file\n", hFile);
	else
		{printf("[-] Failed to open handle to file\n"); return;};


	DWORD file_size = GetFileSize(hFile, 0);
	char* file_buffer = (char*)malloc(file_size);


	BOOL bRead = ReadFile(hFile, file_buffer, file_size, 0, 0);
	if (bRead || !file_size)
		printf("[+] Read content of DLL file\n");
	else
		{printf("[-] Failed to read content of DLL file\n"); return;}


	uint64_t PID = get_pid_by_name(argv[1]);
	if (PID)
		printf("[+] Found process %s with pid %d\n", argv[1], PID);
	else
		{printf("[-] Failed to find process %s pid \n", argv[1]); return;};


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess)
		printf("[+] Opened handle 0x%X to process\n", hProcess);
	else
		{printf("[-] Failed to open handle to process\n"); return;};


	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buffer;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((char*)file_buffer + dos_header->e_lfanew);

	void* image_base = VirtualAllocEx(hProcess, 0, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (image_base)
		printf("[+] Allocated memory in remote process at 0x%p\n", image_base);
	else
		{printf("[-] Failed to allocate memory in remote process\n"); return;};


	BOOL bWHeader = WriteProcessMemory(hProcess, image_base, file_buffer, nt_header->OptionalHeader.SizeOfHeaders, 0);
	if (bWHeader)
		printf("[+] Wrote PE headers at 0x%p\n", image_base);
	else
		{printf("[-] Failed to write PE headers\n"); return;};

		
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (void*)((char*)image_base + section_header[i].VirtualAddress), (void*)((char*)file_buffer + section_header[i].PointerToRawData), section_header[i].SizeOfRawData, 0);
		printf("[+] Writing section %s at 0x%p\n", section_header[i].Name, (void*)((char*)image_base + section_header[i].VirtualAddress));
	}
	
	free(file_buffer);

	void* library_loader = VirtualAllocEx(hProcess, 0, sizeof(MMAP_DATA_STRUCTURE) + ((char*)stub - (char*)load_library_implementation), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (library_loader)
		printf("[+] Allocated memory in remote process at 0x%p\n", library_loader);
	else
		{printf("[-] Failed to allocate memory in remote process\n"); return;};


	MMAP_DATA_STRUCTURE manual_mapping_data = { 0 };
	manual_mapping_data.image_base = image_base;
	manual_mapping_data.LoadLibraryA_address = LoadLibraryA;
	manual_mapping_data.GetProcAddress_address = GetProcAddress;

	BOOL bData = WriteProcessMemory(hProcess, library_loader, &manual_mapping_data, sizeof(MMAP_DATA_STRUCTURE), 0);
	BOOL bLoader = WriteProcessMemory(hProcess, (void*)((PMMAP_DATA_STRUCTURE)library_loader + 1), load_library_implementation, (char*)stub - (char*)load_library_implementation, 0);

	if (bData && bLoader)
		printf("[+] Wrote loader and module information\n");
	else
		{printf("[-] Failed to write module info and/or loader"); return;}

	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)((PMMAP_DATA_STRUCTURE)library_loader + 1), library_loader, 0, 0);
	if (hThread)
		printf("[+] Created thread with handle 0x%X \n", hThread);
	else
		{printf("[-] Failed to create remote thread\n"); return;};


	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, library_loader, 0, MEM_RELEASE);

	return;
}