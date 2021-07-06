# WinApi Call (import) Obfuscator
Header-only c++ library for obfuscation import winapi functions.
This based on https://github.com/XShar/Win_API_Obfuscation and https://xakep.ru/2018/12/06/hidden-winapi/


### How it work?

Importing win api functions calling by hash-value function 


### How to using?
```c++
//typedef functions
using CREATE_FILE_WINAPI = HANDLE (LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using READ_FILE_WINAPI = BOOL (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,	LPOVERLAPPED lpOverlapped);
using GET_SIZE_FILE_WINAPI = DWORD (HANDLE  hFile, unsigned long* lpFileSizeHigh);

//create class winapi-importer
WinApiImport<CREATE_FILE_WINAPI> api_parser("CreateFileA", "kernel32.dll");
//if import is invalid or wrong - return null pointer
//or auto
std::function<CREATE_FILE_WINAPI> func_api = api_parser.get_function();

//open file for reading
auto hFile = func_api("log.txt", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, nullptr);


//or using like this
const auto f_create_file =WinApiImport<CREATE_FILE_WINAPI>::get_func("BCryptDecrypt", "bcrypt.dll");        

```
