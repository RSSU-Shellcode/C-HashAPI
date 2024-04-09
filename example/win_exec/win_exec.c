#include "types.h"
#include "hash_api.h"

typedef uint(*WinExec)(char* lpCmdLine, uint uCmdShow);

#pragma comment(linker, "/ENTRY:EntryMain")
uint64 EntryMain() {    
    uint64 hash = 0xCA2DBA870B222A04;
    uint64 key  = 0xB725F01C80CE0985;
    WinExec winExec = (WinExec)FindAPI(hash, key);
    if (winExec == 0)
    {
        return 0;
    }
    char cmd[] = { 'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0 };
    return winExec(&cmd[0], 1);
}
