#include <stdio.h>
#include "go_types.h"
#include "hash_api.h"

static bool TestHashAPI();
static bool TestHashAPI64();
static bool TestHashAPI32();
static bool TestFindAPI();

int main()
{
    if (!TestHashAPI64())
    {
        return 1;
    }
    if (!TestHashAPI32())
    {
        return 2;
    }
    if (!TestHashAPI())
    {
        return 3;
    }
    if (!TestFindAPI())
    {
        return 3;
    }
    printf("All tests passed!\n");
    return 0;
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

    printf("========TestHashAPI64 passed=======\n\n");
    return true;
}

static bool TestHashAPI32()
{
    return true;
}

static bool TestHashAPI()
{
    return true;
}

static bool TestFindAPI()
{
    return true;
}
