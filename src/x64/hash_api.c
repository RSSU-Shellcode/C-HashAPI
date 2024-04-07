#include "include/types.h"

#define ROR_BITS 8
#define ROR_SEED (ROR_BITS+1)
#define ROR_KEY  (ROR_BITS+2)
#define ROR_MOD  (ROR_BITS+3)
#define ROR_FUNC (ROR_BITS+4)

uintptr FindAPI(uint64 hash, uint64 key)
{
    uint64 seedHash = calcSeedHash(key);
    uint64 keyHash  = calcKeyHash(seedHash, key);

    uintptr peb = __readgsqword(96);
    uintptr ldr = *(uintptr*)(peb + 24);
    uintptr mod = *(uintptr*)(ldr + 32);

    for (;; mod = *(uintptr*)(mod)) {
        uintptr modName = *(uintptr*)(mod + 80);
        if (modName == 0x00)
        {
            break;
        }
        uintptr modBase = *(uintptr*)(mod + 32);
        uintptr peHeader = modBase + *(uint32*)(modBase + 60);
        // check this module actually a PE64 executable
        if (*(uint16*)(peHeader + 24) != 0x020B) {
            continue;
        }
        // get RVA of export address tables(EAT)
        uint32 eatRVA = *(uint32*)(peHeader + 136);
        if (eatRVA == 0) {
            continue;
        }
        uintptr eat = modBase + eatRVA;
        // calculate module name hash
        uint64 modHash = seedHash;
        uint16 nameLen = *(uint16*)(mod + 74);
        for (uint16 i = 0; i < nameLen; i++)
        {
            byte b = *(byte*)(modName + i);
            if (b >= 'a')
            {
                b -= 0x20;
            }
            modHash = ror64(modHash, ROR_MOD);
            modHash += b;
        }
        // calcualte function name hash
        uint32 numFunc = *(uint32*)(eat + 24);
        uintptr funcNames = modBase + *(uint32*)(eat + 32);
        for (uint32 i = 0; i < numFunc; i++)
        {
            // calculate function name address
            byte* funcName = (byte*)(modBase + *(uint32*)(funcNames + i * 4));
            uint64 funcHash = seedHash;
            for (;;)
            {
                byte b = *funcName;
                funcHash = ror64(funcHash, ROR_FUNC);
                funcHash += b;
                if (b == 0x00)
                {
                    break;
                }
                funcName++;
            }
            // calculate the finally hash and compare it
            uint64 apiHash = seedHash + keyHash + modHash + funcHash;
            if (apiHash != hash) {
                continue;
            }
            // calculate the ordinal table
            uintptr funcTable = modBase + *(uint32*)(eat + 28);
            // calculate the desired functions ordinal
            uintptr ordinalTable = modBase + *(uint32*)(eat + 36);
            uint16 ordinal = *(uint16*)(ordinalTable + i * 2);
            // calculate the function address
            return modBase + *(uint32*)(funcTable + ordinal * 4);
        }
    }
    return 0;
}

static uint64 calcSeedHash(uint64 key)
{
    uint64 hash = key;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < 8; i++)
    {
        hash = ror64(hash, ROR_SEED);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint64 calcKeyHash(uint64 seed, uint64 key)
{
    uint64 hash = seed;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < 8; i++)
    {
        hash = ror64(hash, ROR_KEY);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint64 ror64(uint64 value, uint64 bits)
{
    return value >> bits | value << (64 - bits);
}
