#include <stdio.h>
#include <windows.h>
#include "test.h"
#include "c_types.h"
#include "hash_api.h"

bool TestHashAPI64()
{
    byte*  module_a = "kernel32.dll";
    byte*  module_w = L"kernel32.dll";
    byte*  function = "WinExec";
    uint64 hash_key = 0x6A6867C72D518853;

    uint64 hash_a = HashAPI64_A(module_a, function, hash_key);
    uint64 hash_w = HashAPI64_W(module_w, function, hash_key);

    if (hash_a != 0xD2A4AE1BF1F15E57)
    {
        printf("hash is incorrect\n");
        return false;
    }
    printf("hash: 0x%llX\n", hash_a);
    printf("key:  0x%llX\n", hash_key);

    if (hash_a != hash_w)
    {
        printf("hash is not equal\n");
        return false;
    }
    return true;
}

bool TestHashAPI32()
{
    byte*  module_a = "kernel32.dll";
    byte*  module_w = L"kernel32.dll";
    byte*  function = "WinExec";
    uint32 hash_key = 0xCADE960B;

    uint32 hash_a = HashAPI32_A(module_a, function, hash_key);
    uint32 hash_w = HashAPI32_W(module_w, function, hash_key);

    if (hash_a != 0xBB27B6F4)
    {
        printf("hash is incorrect\n");
        return false;
    }
    printf("hash: 0x%lX\n", hash_a);
    printf("key:  0x%lX\n", hash_key);

    if (hash_a != hash_w)
    {
        printf("hash is not equal\n");
        return false;
    }
    return true;
}

bool TestHashAPI()
{
    byte*  module_a = "kernel32.dll";
    byte*  module_w = L"kernel32.dll";
    byte*  function = "WinExec";
#ifdef _WIN64
    uint hash_key = 0x6A6867C72D518853;
#elif _WIN32
    uint hash_key = 0xCADE960B;
#endif
    
    uint hash_a = HashAPI_A(module_a, function, hash_key);
    uint hash_w = HashAPI_W(module_w, function, hash_key);

#ifdef _WIN64
    if (hash_a != 0xD2A4AE1BF1F15E57)
#elif _WIN32
    if (hash_a != 0xBB27B6F4)
#endif
    {
        printf("hash is incorrect\n");
        return false;
    }
    printf("hash: 0x%llX\n", (uint64)hash_a);
    printf("key:  0x%llX\n", (uint64)hash_key);

    if (hash_a != hash_w)
    {
        printf("hash is not equal\n");
        return false;
    }
    return true;
}

bool TestFindAPI()
{
    byte* module   = "kernel32.dll";
    byte* function = "WinExec";
#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    uint hash = HashAPI_A(module, function, key);

    uintptr proc = FindAPI(hash, key);
    if (proc != (uintptr)(&WinExec))
    {
        printf("Proc: %llX\n", (uint64)proc);
        printf("WinExec: %llX\n", (uint64)(&WinExec));
        printf("WinExec address is incorrect\n");
        return false;
    }
    printf("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

bool TestForwarded()
{
    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (hModule == NULL)
    {
        printf("failed to load kernel32.dll\n");
        return false;
    }
    uintptr closeState = GetProcAddress(hModule, "CloseState");

    byte* module   = "kernel32.dll";
    byte* function = "CloseState";
#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    uint hash = HashAPI_A(module, function, key);

    uintptr proc = FindAPI(hash, key);
    if (proc != closeState)
    {
        printf("Proc: %llX\n", (uint64)proc);
        printf("CloseState: %llX\n", (uint64)closeState);
        printf("CloseState address is incorrect\n");
        return false;
    }
    printf("CloseState: 0x%llX\n", (uint64)proc);
    return true;
}
