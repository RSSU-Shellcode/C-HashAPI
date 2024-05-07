#include <stdio.h>
#include <windows.h>
#include "go_types.h"
#include "hash_api.h"

#define BANNER_TOTAL_SIZE 64
#define BANNER_BEGIN_SIZE 10 // strlen("Test begin")
#define BANNER_PASS_SIZE  11 // strlen("Test passed")
#define BANNER_FAIL_SIZE  11 // strlen("Test failed")

static printBannerBegin(byte* name, uint len);
static printBannerEnd(byte* name, uint len, bool pass);

static bool TestHashAPI();
static bool TestHashAPI64();
static bool TestHashAPI32();
static bool TestFindAPI();

int main()
{
    typedef bool (*test_t)();
    typedef struct { byte* Name; test_t Test; } unit;
    unit tests[] = {
        { "HashAPI"  , TestHashAPI   },
        { "HashAPI64", TestHashAPI64 },
        { "HashAPI32", TestHashAPI32 },
        { "FindAPI"  , TestFindAPI   },
    };

    // calculate the banner length
    uint maxNameLen = 0;
    for (int i = 0; i < arrlen(tests); i++)
    {
        uint len = strlen_a(tests[i].Name);
        if (len > maxNameLen)
        {
            maxNameLen = len;
        }
    }
    

    // run unit tests
    bool fail = false;
    for (int i = 0; i < arrlen(tests); i++)
    {
        printBannerBegin(tests[i].Name, maxNameLen);
        bool pass = tests[i].Test();
        if (!pass)
        {
            fail = true;
        }
        printBannerEnd(tests[i].Name, maxNameLen, pass);
    }

    if (fail)
    {
        printf("Failed to test\n");
        return 1;
    }
    printf("All tests passed!\n");
    return 0;
}

static printBannerBegin(byte* name, uint len)
{
    uint padLen = (BANNER_TOTAL_SIZE - BANNER_BEGIN_SIZE - len) / 2;
    bool equal  = (BANNER_TOTAL_SIZE - BANNER_BEGIN_SIZE - len) % 2 == 0;
    for (uint i = 0; i < padLen; i++)
    {
        printf("=");
    }
    printf("Test%s begin", name);
    for (uint i = 0; i < padLen; i++)
    {
        printf("=");
    }
    if (!equal)
    {
        printf("=");
    }
    printf("\n");
}

static printBannerEnd(byte* name, uint len, bool pass)
{

}

static bool TestHashAPI64()
{
    printf("========TestHashAPI64 begin========\n");

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

    printf("========TestHashAPI64 passed=======\n");
    return true;
}

static bool TestHashAPI32()
{
    printf("========TestHashAPI32 begin========\n");

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

    printf("========TestHashAPI32 passed=======\n");
    return true;
}

static bool TestHashAPI()
{
    printf("=========TestHashAPI begin=========\n");

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

    printf("=========TestHashAPI passed========\n");
    return true;
}

static bool TestFindAPI()
{
    printf("=========TestFindAPI begin=========\n");

    byte* module   = "kernel32.dll";
    byte* function = "WinExec";
#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    uint hash = HashAPI_A(module, function, key);

    uintptr winExec = FindAPI(hash, key);
    if (winExec != (uintptr)(&WinExec))
    {
        printf("WinExec address is incorrect\n");
        return false;
    }
    printf("WinExec: 0x%llX\n", (uint64)winExec);

    printf("=========TestFindAPI passed========\n");
    return true;
}
