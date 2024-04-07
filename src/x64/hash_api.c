#include "include/types.h"

#define ROR_BITS 8
#define ROR_SEED (ROR_BITS+1)
#define ROR_KEY  (ROR_BITS+2)
#define ROR_MOD  (ROR_BITS+3)
#define ROR_FUNC (ROR_BITS+4)

uintptr FindAPI(uint hash, uint key)
{
    uint seed_hash = calcSeedHash(key);
    uint key_hash = calcKeyHash(seed_hash, key);
    uintptr peb = __readgsqword(96);
    uintptr ldr = *(uintptr*)(peb + 24);
    uintptr mod = *(uintptr*)(ldr + 32);
    for (;; mod = *(uintptr*)(mod)) {
        uintptr mod_name = *(uintptr*)(mod + 80);
        if (mod_name == 0x00)
        {
            break;
        }
        uintptr mod_base = *(uintptr*)(mod + 32);
        uintptr pe_header = mod_base + *(uint32*)(mod_base + 60);
        // check this module actually a PE64 executable
        if (*(uint16*)(pe_header + 24) != 0x020B) {
            continue;
        }
        // get RVA of export address tables(EAT)
        uint32 eat_rva = *(uint32*)(pe_header + 136);
        if (eat_rva == 0) {
            continue;
        }
        uintptr eat = mod_base + eat_rva;
        // calculate module name hash
        uint mod_hash = seed_hash;
        uint16 name_len = *(uint16*)(mod + 74);
        for (uint16 i = 0; i < name_len; i++)
        {
            byte b = *(byte*)(mod_name + i);
            if (b >= 'a')
            {
                b -= 0x20;
            }
            mod_hash = ror64(mod_hash, ROR_MOD);
            mod_hash += b;
        }
        // calcualte function name hash
        uint32 num_func = *(uint32*)(eat + 24);
        uintptr func_names = mod_base + *(uint32*)(eat + 32);
        for (uint32 i = 0; i < num_func; i++)
        {
            // calculate function name address
            byte* func_name = (byte*)(mod_base + *(uint32*)(func_names + i * 4));
            uint func_hash = seed_hash;
            for (;;)
            {
                byte b = *func_name;
                func_hash = ror64(func_hash, ROR_FUNC);
                func_hash += b;
                if (b == 0x00)
                {
                    break;
                }
                func_name++;
            }
            // calculate the finally hash and compare it
            uint api_hash = seed_hash + key_hash + mod_hash + func_hash;
            if (api_hash != hash) {
                continue;
            }
            // calculate the ordinal table
            uintptr func_table = mod_base + *(uint32*)(eat + 28);
            // calculate the desired functions ordinal
            uintptr ordinal_table = mod_base + *(uint32*)(eat + 36);
            uint16 ordinal = *(uint16*)(ordinal_table + i * 2);
            // calculate the function address
            return mod_base + *(uint32*)(func_table + ordinal * 4);
        }
    }
    return 0;
}

static uint64 calcSeedHash(uint key)
{
    uint64 hash = key;
    byte* lpKey = (byte*)(&key);
    for (int i = 0; i < 8; i++)
    {
        hash = ror64(hash, ROR_SEED);
        hash += *lpKey;
        lpKey++;
    }
    return hash;
}

static uint64 calcKeyHash(uint seed, uint key)
{
    uint64 hash = seed;
    byte* lpKey = (byte*)(&key);
    for (int i = 0; i < 8; i++)
    {
        hash = ror64(hash, ROR_KEY);
        hash += *lpKey;
        lpKey++;
    }
    return hash;
}

static uint64 ror64(uint64 value, uint64 bits)
{
    return value >> bits | value << (64 - bits);
}
