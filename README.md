# Manual mapping - DLL Injection

## Differences

In the previous repo we used ```LoadLibraryA``` to load a DLL into a remote process. This time we will do things differently. We will implement our own function to inject the DLL by parsing its data and writing each section step by step. 

## Steps for injection

We need to read the PE headers of our DLL to determine the number of sections it has and their size. The windows API gives us alot of structures to parse the data of these headers. The basic idea is read data, cast that to the appropriate structure. I recommend you read more about the [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) to understand the meaning of all the strucures used here such as ```IMAGE_OPTIONAL_HEADER``` or ```IMAGE_IMPORT_DESCRIPTOR```.

Once we have the required data about our DLL, we allocate (using ```VirtualAllocEx```) enough memory for it in the remote process and write (using ```WriteProcessMemory```) each section of it one by one :

```cpp
for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
  WriteProcessMemory(hProcess, (void*)((char*)image_base + section_header[i].VirtualAddress), 
  (void*)((char*)file_buffer + section_header[i].PointerToRawData), section_header[i].SizeOfRawData, 0);
```

Great, the remote process now has all of the data it needs to be executed, however the data isn't organized properly to be ran in another process's enviroment. Simply starting a thread at that location won't work. We now need to create a loader that will run in the remote process and fix the ```Import Address Table```(aka IAT). It does so by looping through the imports our DLL, and using ```GetProcAddress``` to find the addresses of each import in the remote process : 

```cpp
*function_ref = (uint64_t)(manual_map_data->GetProcAddress(hDll, MAKEINTRESOURCEA(*thunk_reference)));
```

If our DLL has an entrypoint, we execute it by casting it to a function template that matches the [DllMain](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain) convention:

```cpp
typedef BOOL(__stdcall* dll_main)(HMODULE, DWORD, void*);

if (optional_header->AddressOfEntryPoint)
  {
    dll_main entry_point = (dll_main)(base_address + optional_header->AddressOfEntryPoint);
    entry_point((HMODULE)(manual_mapping_data->image_base), DLL_PROCESS_ATTACH, 0);
  }
  ```
  
  We can now write our loader in the remote process and use `CreateRemoteThread` to run it and start a new thread of execution in the remote process.

## Showcase

![image](https://cdn.discordapp.com/attachments/780153367305256981/1018640843101442179/demo_map.gif)
