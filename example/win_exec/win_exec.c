#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"

#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain() {
#ifdef _WIN64
    uint hash = 0x4BBDC64FE359FC5A;
    uint key  = 0xD7D68112BE34E158;
#elif _WIN32
    uint hash = 0x0AE20914;
    uint key  = 0x61DA2999;
#endif
    WinExec_t winExec = FindAPI(hash, key);
    if (winExec == NULL)
    {
        return 1;
    }
    char cmd[] = {'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0};
    return winExec(&cmd[0], 1);
}
