#include <stdio.h>
#include "go_types.h"
#include "hash_api.h"

int main()
{
    byte module_a[] = "kernel32.dll";
    byte function[] = "WinExec";
    uint key = 0x6A6867C72D518853;

    byte module_w[arrlen(module_a)*2];
    for (int i = 0; i < arrlen(module_a); i++)
    {
        module_w[i*2+0] = module_a[i];
        module_w[i*2+1] = 0x00;
    }
    
    uint hash_a = HashAPI_A(&module_a[0], &function[0], key);
    uint hash_w = HashAPI_W(&module_w[0], &function[0], key);

    printf("0x%llX\n", hash_a);
    printf("0x%llX\n", hash_w);
    return 0;
}
