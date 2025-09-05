#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"

#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain() {
#ifdef _WIN64
    uint mHash = 0x2A5175AD1A0CECBC;
    uint pHash = 0x6596B31A1F68D830;
    uint hKey  = 0x7A61A1C72F518C54;
#elif _WIN32
    uint mHash = 0x42509A1C;
    uint pHash = 0x3CA3C21A;
    uint hKey  = 0xCADE960B;
#endif
    WinExec_t WinExec = FindAPI(mHash, pHash, hKey);
    if (WinExec == NULL)
    {
        return 1;
    }
    char cmd[] = {'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0};
    return WinExec(cmd, 1);
}
