#include "types.h"
#include "hash_api.h"

typedef uint(*WinExec)(char* lpCmdLine, uint uCmdShow);

#pragma comment(linker, "/ENTRY:EntryMain")
uint64 EntryMain() {    
    uint64 hash = 0x4BBDC64FE359FC5A;
    uint64 key  = 0xD7D68112BE34E158;
    WinExec winExec = (WinExec)FindAPI(hash, key);
    if (winExec == NULL)
    {
        return 0;
    }
    char cmd[] = {'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0};
    return winExec(&cmd[0], 1);
}
