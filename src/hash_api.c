#include "go_types.h"
#include "hash_api.h"

#ifdef _WIN64
    #define KEY_SIZE 8
    #define ROR_BITS 8
#elif _WIN32
    #define KEY_SIZE 4
    #define ROR_BITS 4
#endif
#define ROR_SEED (ROR_BITS + 1)
#define ROR_KEY  (ROR_BITS + 2)
#define ROR_MOD  (ROR_BITS + 3)
#define ROR_FUNC (ROR_BITS + 4)

#define KEY_SIZE_64 8
#define ROR_BITS_64 8
#define ROR_SEED_64 (ROR_BITS_64 + 1)
#define ROR_KEY_64  (ROR_BITS_64 + 2)
#define ROR_MOD_64  (ROR_BITS_64 + 3)
#define ROR_FUNC_64 (ROR_BITS_64 + 4)

#define KEY_SIZE_32 4
#define ROR_BITS_32 4
#define ROR_SEED_32 (ROR_BITS_32 + 1)
#define ROR_KEY_32  (ROR_BITS_32 + 2)
#define ROR_MOD_32  (ROR_BITS_32 + 3)
#define ROR_FUNC_32 (ROR_BITS_32 + 4)

static uint calcSeedHash(uint key);
static uint calcKeyHash(uint seed, uint key);
static uint ror(uint value, uint bits);

static uint64 calcSeedHash64(uint64 key);
static uint64 calcKeyHash64(uint64 seed, uint64 key);
static uint64 ror64(uint64 value, uint64 bits);

static uint32 calcSeedHash32(uint32 key);
static uint32 calcKeyHash32(uint32 seed, uint32 key);
static uint32 ror32(uint32 value, uint32 bits);

uintptr FindAPI(uint hash, uint key)
{
    uint seedHash = calcSeedHash(key);
    uint keyHash  = calcKeyHash(seedHash, key);
#ifdef _WIN64
    uintptr peb = __readgsqword(96);
    uintptr ldr = *(uintptr*)(peb + 24);
    uintptr mod = *(uintptr*)(ldr + 32);
#elif _WIN32
    uintptr peb = __readfsdword(48);
    uintptr ldr = *(uintptr*)(peb + 12);
    uintptr mod = *(uintptr*)(ldr + 20);
#endif
    for (;; mod = *(uintptr*)(mod))
    {
    #ifdef _WIN64
        uintptr modName = *(uintptr*)(mod + 80);
    #elif _WIN32
        uintptr modName = *(uintptr*)(mod + 40);
    #endif    
        if (modName == 0x00)
        {
            break;
        }
    #ifdef _WIN64
        uintptr modBase = *(uintptr*)(mod + 32);
    #elif _WIN32
        uintptr modBase = *(uintptr*)(mod + 16);
    #endif
        uintptr peHeader = modBase + *(uint32*)(modBase + 60);
    #ifdef _WIN64
        // check this module actually a PE64 executable
        if (*(uint16*)(peHeader + 24) != 0x020B)
        {
            continue;
        }
    #endif
        // get RVA of export address tables(EAT)
    #ifdef _WIN64
        uint32 eatRVA = *(uint32*)(peHeader + 136);
    #elif _WIN32
        uint32 eatRVA = *(uint32*)(peHeader + 120);
    #endif
        if (eatRVA == 0)
        {
            continue;
        }
        uintptr eat = modBase + eatRVA;
        // calculate module name hash
        uint modHash = seedHash;
    #ifdef _WIN64
        uint16 nameLen = *(uint16*)(mod + 74);
    #elif _WIN32
        uint16 nameLen = *(uint16*)(mod + 38);
    #endif
        for (uint16 i = 0; i < nameLen; i++)
        {
            byte b = *(byte*)(modName + i);
            if (b >= 'a')
            {
                b -= 0x20;
            }
            modHash = ror(modHash, ROR_MOD);
            modHash += b;
        }
        // calculate function name hash
        uint32  numFunc   = *(uint32*)(eat + 24);
        uintptr funcNames = modBase + *(uint32*)(eat + 32);
        for (uint32 i = 0; i < numFunc; i++)
        {
            // calculate function name address
            byte* funcName = (byte*)(modBase + *(uint32*)(funcNames + i * 4));
            uint  funcHash = seedHash;
            for (;;)
            {
                byte b = *funcName;
                funcHash = ror(funcHash, ROR_FUNC);
                funcHash += b;
                if (b == 0x00)
                {
                    break;
                }
                funcName++;
            }
            // calculate the finally hash and compare it
            uint h = seedHash + keyHash + modHash + funcHash;
            if (h != hash) 
            {
                continue;
            }
            // calculate the ordinal table
            uintptr funcTable = modBase + *(uint32*)(eat + 28);
            // calculate the desired functions ordinal
            uintptr ordinalTable = modBase + *(uint32*)(eat + 36);
            // calculate offset of ordinal
            uint16 ordinal = *(uint16*)(ordinalTable + i * 2);
            // calculate the function address
            return modBase + *(uint32*)(funcTable + ordinal * 4);
        }
    }
    return NULL;
}

uint HashAPI64_A(byte* module, byte* function, uint64 key)
{
    uint seedHash = calcSeedHash(key);
    uint keyHash  = calcKeyHash(seedHash, key);
    // calculate module hash
    uint modHash  = seedHash;
    for (;;)
    {
        byte b = *module;
        if (b >= 'a')
        {
            b -= 0x20;
        }
        modHash = ror(modHash, ROR_MOD);
        modHash += b;
        modHash = ror(modHash, ROR_MOD);
        if (b == 0x00)
        {
            break;
        }
        module++;
    }
    // calculate function hash
    uint funcHash = seedHash;
    for (;;)
    {
        byte b = *function;
        funcHash = ror(funcHash, ROR_FUNC);
        funcHash += b;
        if (b == 0x00)
        {
            break;
        }
        function++;
    }
    return seedHash + keyHash + modHash + funcHash;
}

uint HashAPI64_W(byte* module, byte* function, uint key)
{
    uint seedHash = calcSeedHash(key);
    uint keyHash  = calcKeyHash(seedHash, key);
    // calculate module hash
    uint modHash = seedHash;
    for (;;)
    {
        byte b0 = *(module + 0);
        byte b1 = *(module + 1);
        if (b0 >= 'a')
        {
            b0 -= 0x20;
        }
        modHash = ror(modHash, ROR_MOD);
        modHash += b0;
        modHash = ror(modHash, ROR_MOD);
        modHash += b1;
        if (b0 == 0x00 && b1 == 0x00)
        {
            break;
        }
        module += 2;
    }
    // calculate function hash
    uint funcHash = seedHash;
    for (;;)
    {
        byte b = *function;
        funcHash = ror(funcHash, ROR_FUNC);
        funcHash += b;
        if (b == 0x00)
        {
            break;
        }
        function++;
    }
    return seedHash + keyHash + modHash + funcHash;
}

static uint calcSeedHash(uint key)
{
    uint  hash = key;
    byte* ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE; i++)
    {
        hash = ror(hash, ROR_SEED);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint calcKeyHash(uint seed, uint key)
{
    uint  hash = seed;
    byte* ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE; i++)
    {
        hash = ror(hash, ROR_KEY);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint ror(uint value, uint bits)
{
#ifdef _WIN64
    return value >> bits | value << (64 - bits);
#elif _WIN32
    return value >> bits | value << (32 - bits);
#endif
}

static uint64 calcSeedHash64(uint64 key)
{
    uint64 hash = key;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < 8; i++)
    {
        hash = ror64(hash, 8 + 1);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint64 calcKeyHash64(uint64 seed, uint64 key)
{
    uint64 hash = seed;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < 8; i++)
    {
        hash = ror64(hash, 8 + 2);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint64 ror64(uint64 value, uint64 bits)
{
    return value >> bits | value << (64 - bits);
}

static uint32 calcSeedHash32(uint32 key)
{
    uint32 hash = key;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < 4; i++)
    {
        hash = ror32(hash, 4 + 1);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint32 calcKeyHash32(uint32 seed, uint32 key)
{
    uint32 hash = seed;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < 4; i++)
    {
        hash = ror32(hash, 4 + 2);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint32 ror32(uint32 value, uint32 bits)
{
    return value >> bits | value << (32 - bits);
}
