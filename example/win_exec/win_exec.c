#include "go_types.h"
#include "hash_api.h"

typedef byte* LPCSTR;
typedef uint (*WinExec)(LPCSTR lpCmdLine, uint uCmdShow);

#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain() {
#ifdef _WIN64
    uint hash = 0x4BBDC64FE359FC5A;
    uint key  = 0xD7D68112BE34E158;
#elif _WIN32
    uint hash = 0x0AE20914;
    uint key  = 0x61DA2999;
#endif
    WinExec winExec = (WinExec)FindAPI(hash, key);
    if (winExec == NULL)
    {
        return 0;
    }
    byte cmd[] = {'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0};
    return winExec(&cmd[0], 1);
}
