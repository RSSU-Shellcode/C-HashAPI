#pragma warning(disable: 4668)

#include <stdio.h>
#include <windows.h>
#include "c_types.h"
#include "hash_api.h"
#include "test.h"

bool TestFindAPI()
{
    byte* module    = "kernel32.dll";
    byte* procedure = "WinExec";
#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    uint modHash  = CalcModHash_A(module, key);
    uint procHash = CalcProcHash(procedure, key);

    void* proc = FindAPI(modHash, procHash, key);
    if (proc != &WinExec)
    {
        printf_s("Result:  %llX\n", (uint64)proc);
        printf_s("WinExec: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

bool TestFindAPI_ML()
{
    byte* module    = "kernel32.dll";
    byte* procedure = "WinExec";
#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    uintptr list  = GetInMemoryOrderModuleList();
    uint modHash  = CalcModHash_A(module, key);
    uint procHash = CalcProcHash(procedure, key);

    void* proc = FindAPI_ML(list, modHash, procHash, key);
    if (proc != &WinExec)
    {
        printf_s("Result:  %llX\n", (uint64)proc);
        printf_s("WinExec: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

bool TestFindAPI_A()
{
    byte* module    = "kernel32.dll";
    byte* procedure = "WinExec";

    void* proc = FindAPI_A(module, procedure);
    if (proc != &WinExec)
    {
        printf_s("Result:  %llX\n", (uint64)proc);
        printf_s("WinExec: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

bool TestFindAPI_W()
{
    uint16* module    = L"kernel32.dll";
    byte*   procedure = "WinExec";

    void* proc = FindAPI_W(module, procedure);
    if (proc != &WinExec)
    {
        printf_s("Result:  %llX\n", (uint64)proc);
        printf_s("WinExec: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

bool TestForwarded()
{
    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (hModule == NULL)
    {
        printf_s("failed to load kernel32.dll\n");
        return false;
    }
    void* closeState = GetProcAddress(hModule, "CloseState");

    byte* module    = "kernel32.dll";
    byte* procedure = "CloseState";
#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    uint modHash  = CalcModHash_A(module, key);
    uint procHash = CalcProcHash(procedure, key);

    void* proc = FindAPI(modHash, procHash, key);
    if (proc != closeState)
    {
        printf_s("Result:     %llX\n", (uint64)proc);
        printf_s("CloseState: %llX\n", (uint64)closeState);
        printf_s("CloseState address is incorrect\n");
        return false;
    }
    printf_s("CloseState: 0x%llX\n", (uint64)proc);
    return true;
}

bool TestCalcModHash32()
{
    byte*   module_a = "kernel32.dll";
    uint16* module_w = L"kernel32.dll";
    uint32  key      = 0xCADE960B;
    
    uint32 hash_a = CalcModHash32_A(module_a, key);
    uint32 hash_w = CalcModHash32_W(module_w, key);
    
    printf_s("hash: 0x%X\n", hash_a);
    if (hash_a != 0x42509A1C)
    {
        printf_s("hash is incorrect\n");
        return false;
    }
    if (hash_a != hash_w)
    {
        printf_s("hash is not equal\n");
        return false;
    }
    return true;
}

bool TestCalcModHash64()
{
    byte*   module_a = "kernel32.dll";
    uint16* module_w = L"kernel32.dll";
    uint64  key      = 0x6A6867C72D518853;
    
    uint64 hash_a = CalcModHash64_A(module_a, key);
    uint64 hash_w = CalcModHash64_W(module_w, key);

    printf_s("hash: 0x%llX\n", hash_a);
    if (hash_a != 0x45BC05B44B0BA44)
    {
        printf_s("hash is incorrect\n");
        return false;
    }
    if (hash_a != hash_w)
    {
        printf_s("hash is not equal\n");
        return false;
    }
    return true;
}

bool TestCalcProcHash32()
{
    return true;
}

bool TestCalcProcHash64()
{
    return true;
}
