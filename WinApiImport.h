#pragma once

#include <functional>
#include <Windows.h>

#if defined (WIN64) || defined(WIN32)

using TLoadLibrary = HMODULE(WINAPI*)(__in LPCSTR file_name);

struct UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct LDR_MODULE
{
    LIST_ENTRY e[3];
    HMODULE base;
    void* entry;
    UINT size;
    UNICODE_STRING dllPath;
    UNICODE_STRING dllname;
};

#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }



template<class T>
class WinApiImport
{
public:
    ~WinApiImport() = default;
    WinApiImport(const char* func_name, const char* module_name, unsigned seed = 0)
        : m_func_name(func_name),
        m_module_name(module_name)
    {
        m_len = strlen(func_name);

        if (seed == 0) m_seed = m_len;

    }

    static std::function<T> get(const char* func_name, const char* module_name, unsigned seed = 0)
    {
        WinApiImport<T> api_import(func_name, module_name, seed);
        return api_import.get_function();
    }

    std::function<T> get_function() {
        try
        {
            HMODULE krnl32, hDll;
            LPVOID api_func;
            DWORD api_hash = murmur_hash2_a(m_func_name, m_len, m_seed);
#ifdef _WIN64
            const auto ModuleList = 0x18;
            const auto ModuleListFlink = 0x18;
            const auto KernelBaseAddr = 0x10;
            const INT_PTR peb = __readgsqword(0x60);
#else
            int ModuleList = 0x0C;
            int ModuleListFlink = 0x10;
            int KernelBaseAddr = 0x10;
            INT_PTR peb = __readfsdword(0x30);
#endif

            // Теперь получим адрес kernel32.dll

            const auto mdllist = *(INT_PTR*)(peb + ModuleList);
            const auto mlink = *(INT_PTR*)(mdllist + ModuleListFlink);
            auto krnbase = *(INT_PTR*)(mlink + KernelBaseAddr);

            auto mdl = (LDR_MODULE*)mlink;
            do
            {
                mdl = (LDR_MODULE*)mdl->e[0].Flink;

                if (mdl->base != nullptr)
                {
                    if (!lstrcmpiW(mdl->dllname.Buffer, L"kernel32.dll")) //сравниваем имя библиотеки в буфере с необходимым
                    {
                        break;
                    }
                }
            } while (mlink != (INT_PTR)mdl);

            krnl32 = static_cast<HMODULE>(mdl->base);

            //Получаем адрес функции LoadLibraryA
            const int api_hash_LoadLibraryA = murmur_hash2_a("LoadLibraryA", 12, 10);
            auto temp_LoadLibraryA = static_cast<TLoadLibrary>(parse_export_table(krnl32, api_hash_LoadLibraryA, 12, 10));
            hDll = temp_LoadLibraryA(m_module_name);

            api_func = parse_export_table(hDll, api_hash, m_len, m_seed);


            return std::move(std::function<T>(static_cast<T*>(api_func)));
        }
        catch (...)
        {

            return nullptr;
        }

    };




private:
    const char* m_func_name;
    const char* m_module_name;
    int m_len;
    unsigned m_seed;

    LPVOID parse_export_table(HMODULE module, DWORD api_hash, int len, unsigned seed) {
        try
        {
            PIMAGE_DOS_HEADER img_dos_header;
            PIMAGE_NT_HEADERS img_nt_header;
            PIMAGE_EXPORT_DIRECTORY in_export;

            img_dos_header = (PIMAGE_DOS_HEADER)module;
            img_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)img_dos_header + img_dos_header->e_lfanew);
            in_export = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)img_dos_header + img_nt_header->OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            PDWORD rva_name;
            PWORD rva_ordinal;

            rva_name = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNames);
            rva_ordinal = (PWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNameOrdinals);

            UINT ord = -1;
            char* api_name;
            unsigned int i;

            for (i = 0; i < in_export->NumberOfNames - 1; i++)
            {
                api_name = (PCHAR)((DWORD_PTR)img_dos_header + rva_name[i]);

                const int get_hash = murmur_hash2_a(api_name, len, seed);

                if (api_hash == get_hash)
                {
                    ord = static_cast<UINT>(rva_ordinal[i]);
                    break;
                }
            }

            const auto func_addr = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfFunctions);

            if (ord > reinterpret_cast<unsigned>(func_addr)) return nullptr;

            const auto func_find = (LPVOID)((DWORD_PTR)img_dos_header + func_addr[ord]);

            return func_find;
        }
        catch (...)
        {
            return nullptr;
        }

    };

    unsigned int murmur_hash2_a(const void* key, int len, unsigned int seed) {
        const unsigned int m = 0x5bd1e995;
        const auto r = 24;
        unsigned int l = len;
        auto data = static_cast<const unsigned char*>(key);

        auto h = seed;
        unsigned int k;

        while (len >= 4)
        {
            k = *(unsigned int*)data;

            mmix(h, k);

            data += 4;
            len -= 4;
        }

        unsigned int t = 0;

        switch (len)
        {
        case 3: t ^= data[2] << 16;
        case 2: t ^= data[1] << 8;
        case 1: t ^= data[0];
        };

        mmix(h, t);
        mmix(h, l);

        h ^= h >> 13;
        h *= m;
        h ^= h >> 15;

        return h;
    };
};

#endif





